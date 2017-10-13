#ifdef _MSC_VER
#  include <winsock2.h>
#  include <windows.h>
#else
#  include <sys/time.h>
#endif

#ifdef _GNU_SOURCE
#  include <errno.h>
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
#include "TracyScoped.hpp"
#include "TracyProfiler.hpp"

#ifdef _DEBUG
#  define DISABLE_LZ4
#endif

#ifdef __GNUC__
#define init_order( val ) __attribute__ ((init_priority(val)))
#else
#define init_order(x)
#endif

namespace tracy
{

static const char* GetProcessName()
{
#if defined _MSC_VER
    static char buf[_MAX_PATH];
    GetModuleFileNameA( nullptr, buf, _MAX_PATH );
    const char* ptr = buf;
    while( *ptr != '\0' ) ptr++;
    while( ptr > buf && *ptr != '\\' && *ptr != '/' ) ptr--;
    if( ptr > buf ) ptr++;
    return ptr;
#elif defined _GNU_SOURCE
    return program_invocation_short_name;
#else
    return "unknown";
#endif
}

enum { QueuePrealloc = 256 * 1024 };

static moodycamel::ConcurrentQueue<QueueItem> init_order(101) s_queue( QueueItemSize * QueuePrealloc );
static thread_local moodycamel::ProducerToken init_order(102) s_token_detail( s_queue );
thread_local ProducerWrapper init_order(103) s_token { s_queue.get_explicit_producer( s_token_detail ) };

std::atomic<uint64_t> s_id( 0 );

#ifndef TRACY_DISABLE
static Profiler init_order(104) s_profiler;
#endif

static Profiler* s_instance = nullptr;

Profiler::Profiler()
    : m_mainThread( GetThreadHandle() )
    , m_epoch( std::chrono::duration_cast<std::chrono::seconds>( std::chrono::system_clock::now().time_since_epoch() ).count() )
    , m_shutdown( false )
    , m_stream( LZ4_createStream() )
    , m_buffer( new char[TargetFrameSize*3] )
    , m_bufferOffset( 0 )
{
    assert( !s_instance );
    s_instance = this;

    CalibrateTimer();
    CalibrateDelay();
    uint32_t cpu;
    m_timeBegin = GetTime( cpu );

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
            const auto procname = GetProcessName();
            const auto pnsz = std::min<size_t>( strlen( procname ), WelcomeMessageProgramNameSize - 1 );

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
            welcome.resolution = m_resolution;
            welcome.epoch = m_epoch;
            memcpy( welcome.programName, procname, pnsz );
            memset( welcome.programName + pnsz, 0, WelcomeMessageProgramNameSize - pnsz );

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
    assert( type == QueueType::StringData || type == QueueType::ThreadName || type == QueueType::CustomStringData || type == QueueType::PlotName );

    QueueItem item;
    item.hdr.type = type;
    item.stringTransfer.ptr = str;

    const auto isz = QueueDataSize[item.hdr.idx];

    auto buf = m_buffer + m_bufferOffset;
    memcpy( buf, &item, isz );

    auto len = strlen( ptr );
    assert( len < TargetFrameSize - isz - sizeof( uint16_t ) );
    assert( len <= std::numeric_limits<uint16_t>::max() );
    uint16_t l16 = len;
    memcpy( buf + isz, &l16, sizeof( l16 ) );
    memcpy( buf + isz + sizeof( l16 ), ptr, l16 );

    m_bufferOffset += isz + sizeof( l16 ) + l16;
    if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;

    return SendData( buf, isz + sizeof( l16 ) + l16 );
}

void Profiler::SendSourceLocation( uint64_t ptr )
{
    auto srcloc = (const SourceLocation*)ptr;
    QueueItem item;
    item.hdr.type = QueueType::SourceLocation;
    item.srcloc.ptr = ptr;
    item.srcloc.file = (uint64_t)srcloc->file;
    item.srcloc.function = (uint64_t)srcloc->function;
    item.srcloc.line = srcloc->line;
    item.srcloc.r = ( srcloc->color       ) & 0xFF;
    item.srcloc.g = ( srcloc->color >> 8  ) & 0xFF;
    item.srcloc.b = ( srcloc->color >> 16 ) & 0xFF;
    s_token.ptr->enqueue<moodycamel::CanAlloc>( std::move( item ) );
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
    case ServerQueryPlotName:
        SendString( ptr, (const char*)ptr, QueueType::PlotName );
        break;
    default:
        assert( false );
        break;
    }

    return true;
}

void Profiler::CalibrateTimer()
{
#ifdef TRACY_RDTSCP_SUPPORTED
    uint32_t cpu;
    std::atomic_signal_fence( std::memory_order_acq_rel );
    const auto t0 = std::chrono::high_resolution_clock::now();
    const auto r0 = tracy_rdtscp( cpu );
    std::atomic_signal_fence( std::memory_order_acq_rel );
    std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
    std::atomic_signal_fence( std::memory_order_acq_rel );
    const auto t1 = std::chrono::high_resolution_clock::now();
    const auto r1 = tracy_rdtscp( cpu );
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
    FakeZone( const SourceLocation* srcloc ) : m_id( (uint64_t)srcloc ) {}
    ~FakeZone() {}

private:
    volatile uint64_t m_id;
};

void Profiler::CalibrateDelay()
{
    enum { Iterations = 50000 };
    enum { Events = Iterations * 2 };   // start + end
    static_assert( Events * 2 < QueuePrealloc, "Delay calibration loop will allocate memory in queue" );

    uint32_t cpu;
    moodycamel::ProducerToken ptoken_detail( s_queue );
    moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* ptoken = s_queue.get_explicit_producer( ptoken_detail );
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocation __tracy_source_location { __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 };
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::ZoneBegin;
            item->zoneBegin.thread = GetThreadHandle();
            item->zoneBegin.time = GetTime( item->zoneBegin.cpu );
            item->zoneBegin.srcloc = (uint64_t)&__tracy_source_location;
            tail.store( magic + 1, std::memory_order_release );
        }
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::ZoneEnd;
            item->zoneEnd.thread = 0;
            item->zoneEnd.time = GetTime( item->zoneEnd.cpu );
            tail.store( magic + 1, std::memory_order_release );
        }
    }
    const auto f0 = GetTime( cpu );
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocation __tracy_source_location { __FUNCTION__,  __FILE__, __LINE__, 0 };
        FakeZone ___tracy_scoped_zone( &__tracy_source_location );
    }
    const auto t0 = GetTime( cpu );
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocation __tracy_source_location { __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 };
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::ZoneBegin;
            item->zoneBegin.thread = GetThreadHandle();
            item->zoneBegin.time = GetTime( item->zoneBegin.cpu );
            item->zoneBegin.srcloc = (uint64_t)&__tracy_source_location;
            tail.store( magic + 1, std::memory_order_release );
        }
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::ZoneEnd;
            item->zoneEnd.thread = 0;
            item->zoneEnd.time = GetTime( item->zoneEnd.cpu );
            tail.store( magic + 1, std::memory_order_release );
        }
    }
    const auto t1 = GetTime( cpu );
    const auto dt = t1 - t0;
    const auto df = t0 - f0;
    m_delay = ( dt - df ) / Events;

    uint64_t mindiff = std::numeric_limits<uint64_t>::max();
    for( int i=0; i<Iterations * 10; i++ )
    {
        const auto t0 = GetTime( cpu );
        const auto t1 = GetTime( cpu );
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
