#ifdef _MSC_VER
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

#include <atomic>
#include <assert.h>
#include <chrono>
#include <limits>
#include <memory>
#include <string.h>

#include "../common/TracyProtocol.hpp"
#include "../common/TracySocket.hpp"
#include "../common/TracySystem.hpp"
#include "concurrentqueue.h"
#include "TracyScoped.hpp"
#include "TracyProfiler.hpp"

#ifdef _DEBUG
#  define DISABLE_LZ4
#endif

namespace tracy
{

enum { QueuePrealloc = 256 * 1024 };

static moodycamel::ConcurrentQueue<QueueItem> s_queue( QueueItemSize * QueuePrealloc );
static thread_local moodycamel::ProducerToken s_token( s_queue );

static std::atomic<uint64_t> s_id( 0 );

static inline uint64_t GetNewId()
{
    return s_id.fetch_add( 1, std::memory_order_relaxed );
}

#ifndef TRACY_DISABLE
static Profiler s_profiler;
#endif

static Profiler* s_instance = nullptr;

static inline uint64_t ZoneBeginImpl( moodycamel::ProducerToken& token, QueueZoneBegin&& data )
{
    auto id = GetNewId();
    QueueItem item;
    item.hdr.type = QueueType::ZoneBegin;
    item.hdr.id = id;
    item.zoneBegin = std::move( data );
    s_queue.enqueue( token, std::move( item ) );
    return id;
}

static inline void ZoneEndImpl( moodycamel::ProducerToken& token, uint64_t id, QueueZoneEnd&& data )
{
    QueueItem item;
    item.hdr.type = QueueType::ZoneEnd;
    item.hdr.id = id;
    item.zoneEnd = std::move( data );
    s_queue.enqueue( token, std::move( item ) );
}

Profiler::Profiler()
    : m_mainThread( GetThreadHandle() )
    , m_shutdown( false )
    , m_stream( LZ4_createStream() )
    , m_buffer( new char[TargetFrameSize*3] )
    , m_bufferOffset( 0 )
{
    assert( !s_instance );
    s_instance = this;

    CalibrateTimer();
    CalibrateDelay();
    m_timeBegin = GetTime();

    m_thread = std::thread( [this] { Worker(); } );
    SetThreadName( m_thread, "Tracy Profiler" );
}

Profiler::~Profiler()
{
    m_shutdown.store( true, std::memory_order_relaxed );
    m_thread.join();

    delete[] m_buffer;
    LZ4_freeStream( m_stream );

    assert( s_instance );
    s_instance = nullptr;
}

uint64_t Profiler::ZoneBegin( QueueZoneBegin&& data )
{
    return ZoneBeginImpl( s_token, std::move( data ) );
}

void Profiler::ZoneEnd( uint64_t id, QueueZoneEnd&& data )
{
    ZoneEndImpl( s_token, id, std::move( data ) );
}

void Profiler::ZoneText( uint64_t id, QueueZoneText&& data )
{
    QueueItem item;
    item.hdr.type = QueueType::ZoneText;
    item.hdr.id = id;
    item.zoneText = std::move( data );
    s_queue.enqueue( s_token, std::move( item ) );
}

void Profiler::ZoneName( uint64_t id, QueueZoneName&& data )
{
    QueueItem item;
    item.hdr.type = QueueType::ZoneName;
    item.hdr.id = id;
    item.zoneName = std::move( data );
    s_queue.enqueue( s_token, std::move( item ) );
}

void Profiler::FrameMark()
{
    QueueItem item;
    item.hdr.type = QueueType::FrameMarkMsg;
    item.hdr.id = (uint64_t)GetTime();
    s_queue.enqueue( s_token, std::move( item ) );
}

bool Profiler::ShouldExit()
{
    return s_instance->m_shutdown.load( std::memory_order_relaxed );
}

void Profiler::Worker()
{
    enum { BulkSize = TargetFrameSize / QueueItemSize };

    moodycamel::ConsumerToken token( s_queue );

    ListenSocket listen;
    listen.Listen( "8086", 8 );

    for(;;)
    {
        for(;;)
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;
            m_sock = listen.Accept();
            if( m_sock ) break;
        }

        {
            WelcomeMessage welcome;
#ifdef DISABLE_LZ4
            // notify client that lz4 compression is disabled (too slow in debug builds)
            welcome.lz4 = 0;
#else
            welcome.lz4 = 1;
#endif
            welcome.timerMul = m_timerMul;
            welcome.timeBegin = m_timeBegin;
            welcome.delay = m_delay;

            m_sock->Send( &welcome, sizeof( welcome ) );
        }

        LZ4_resetStream( m_stream );

        for(;;)
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;

            QueueItem item[BulkSize];
            const auto sz = s_queue.try_dequeue_bulk( token, item, BulkSize );
            if( sz > 0 )
            {
                auto buf = m_buffer + m_bufferOffset;
                auto ptr = buf;
                for( size_t i=0; i<sz; i++ )
                {
                    const auto dsz = QueueDataSize[item[i].hdr.idx];
                    memcpy( ptr, item+i, dsz );
                    ptr += dsz;
                }
                if( !SendData( buf, ptr - buf ) ) break;
                m_bufferOffset += ptr - buf;
                if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;
            }
            else
            {
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }

            while( m_sock->HasData() )
            {
                if( !HandleServerQuery() ) break;
            }
        }
    }
}

bool Profiler::SendData( const char* data, size_t len )
{
#ifdef DISABLE_LZ4
    if( m_sock->Send( data, len ) == -1 ) return false;
#else
    char lz4[LZ4Size + sizeof( lz4sz_t )];
    const lz4sz_t lz4sz = LZ4_compress_fast_continue( m_stream, data, lz4 + sizeof( lz4sz_t ), len, LZ4Size, 1 );
    memcpy( lz4, &lz4sz, sizeof( lz4sz ) );
    if( m_sock->Send( lz4, lz4sz + sizeof( lz4sz_t ) ) == -1 ) return false;
#endif
    return true;
}

bool Profiler::SendString( uint64_t str, const char* ptr, QueueType type )
{
    assert( type == QueueType::StringData || type == QueueType::ThreadName || type == QueueType::CustomStringData );

    QueueHeader hdr;
    hdr.type = type;
    hdr.id = str;

    auto buf = m_buffer + m_bufferOffset;
    memcpy( buf, &hdr, sizeof( hdr ) );

    auto len = strlen( ptr );
    assert( len < TargetFrameSize - sizeof( hdr ) - sizeof( uint16_t ) );
    assert( len <= std::numeric_limits<uint16_t>::max() );
    uint16_t l16 = len;
    memcpy( buf + sizeof( hdr ), &l16, sizeof( l16 ) );
    memcpy( buf + sizeof( hdr ) + sizeof( l16 ), ptr, l16 );

    m_bufferOffset += sizeof( hdr ) + sizeof( l16 ) + l16;
    if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;

    return SendData( buf, sizeof( hdr ) + sizeof( l16 ) + l16 );
}

void Profiler::SendSourceLocation( uint64_t ptr )
{
    auto srcloc = (const SourceLocation*)ptr;
    QueueItem item;
    item.hdr.type = QueueType::SourceLocation;
    item.hdr.id = ptr;
    item.srcloc.file = (uint64_t)srcloc->file;
    item.srcloc.function = (uint64_t)srcloc->function;
    item.srcloc.line = srcloc->line;
    item.srcloc.color = srcloc->color;
    s_queue.enqueue( s_token, std::move( item ) );
}

bool Profiler::HandleServerQuery()
{
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    uint8_t type;
    if( !m_sock->Read( &type, sizeof( type ), &tv, ShouldExit ) ) return false;

    uint64_t ptr;
    if( !m_sock->Read( &ptr, sizeof( ptr ), &tv, ShouldExit ) ) return false;

    switch( type )
    {
    case ServerQueryString:
        SendString( ptr, (const char*)ptr, QueueType::StringData );
        break;
    case ServerQueryThreadString:
        if( ptr == m_mainThread )
        {
            SendString( ptr, "Main thread", QueueType::ThreadName );
        }
        else
        {
            SendString( ptr, GetThreadName( ptr ), QueueType::ThreadName );
        }
        break;
    case ServerQueryCustomString:
        SendString( ptr, (const char*)ptr, QueueType::CustomStringData );
        delete[] (const char*)ptr;
        break;
    case ServerQuerySourceLocation:
        SendSourceLocation( ptr );
        break;
    default:
        assert( false );
        break;
    }

    return true;
}

void Profiler::CalibrateTimer()
{
#if defined _MSC_VER || defined __CYGWIN__
    unsigned int ui;
    std::atomic_signal_fence( std::memory_order_acq_rel );
    const auto t0 = std::chrono::high_resolution_clock::now();
    const auto r0 = __rdtscp( &ui );
    std::atomic_signal_fence( std::memory_order_acq_rel );
    std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
    std::atomic_signal_fence( std::memory_order_acq_rel );
    const auto t1 = std::chrono::high_resolution_clock::now();
    const auto r1 = __rdtscp( &ui );
    std::atomic_signal_fence( std::memory_order_acq_rel );

    const auto dt = std::chrono::duration_cast<std::chrono::nanoseconds>( t1 - t0 ).count();
    const auto dr = r1 - r0;

    m_timerMul = double( dt ) / double( dr );
#else
    m_timerMul = 1.;
#endif
}

class FakeZone
{
public:
    FakeZone( const SourceLocation* srcloc ) {}
    ~FakeZone() {}

private:
    uint64_t m_id;
};

void Profiler::CalibrateDelay()
{
    enum { Iterations = 50000 };
    enum { Events = Iterations * 2 };   // start + end
    static_assert( Events * 2 < QueuePrealloc, "Delay calibration loop will allocate memory in queue" );

    moodycamel::ProducerToken ptoken( s_queue );
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocation __tracy_source_location { __FUNCTION__,  __FILE__, __LINE__, 0 };
        const auto id = ZoneBeginImpl( ptoken, QueueZoneBegin { Profiler::GetTime(), (uint64_t)&__tracy_source_location, GetThreadHandle() } );
        ZoneEndImpl( ptoken, id, QueueZoneEnd { Profiler::GetTime() } );
    }
    const auto f0 = GetTime();
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocation __tracy_source_location { __FUNCTION__,  __FILE__, __LINE__, 0 };
        FakeZone ___tracy_scoped_zone( &__tracy_source_location );
    }
    const auto t0 = GetTime();
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocation __tracy_source_location { __FUNCTION__,  __FILE__, __LINE__, 0 };
        const auto id = ZoneBeginImpl( ptoken, QueueZoneBegin { Profiler::GetTime(), (uint64_t)&__tracy_source_location, GetThreadHandle() } );
        ZoneEndImpl( ptoken, id, QueueZoneEnd { Profiler::GetTime() } );
    }
    const auto t1 = GetTime();
    const auto dt = t1 - t0;
    const auto df = t0 - f0;
    m_delay = ( dt - df ) / Events;

    uint64_t mindiff = std::numeric_limits<uint64_t>::max();
    for( int i=0; i<Iterations * 10; i++ )
    {
        const auto t0 = GetTime();
        const auto t1 = GetTime();
        const auto dt = t1 - t0;
        if( dt > 0 && dt < mindiff ) mindiff = dt;
    }

    m_resolution = mindiff;

    enum { Bulk = 1000 };
    moodycamel::ConsumerToken token( s_queue );
    int left = Events * 2;
    QueueItem item[Bulk];
    while( left != 0 )
    {
        const auto sz = s_queue.try_dequeue_bulk( token, item, std::min( left, (int)Bulk ) );
        assert( sz > 0 );
        left -= sz;
    }
}

}
