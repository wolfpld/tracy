#ifdef TRACY_ENABLE

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
#include <stdlib.h>
#include <string.h>

#include "../common/TracyProtocol.hpp"
#include "../common/TracySocket.hpp"
#include "../common/TracySystem.hpp"
#include "tracy_rpmalloc.hpp"
#include "TracyScoped.hpp"
#include "TracyProfiler.hpp"
#include "TracyThread.hpp"

#ifdef __GNUC__
#define init_order( val ) __attribute__ ((init_priority(val)))
#else
#define init_order(x)
#endif

namespace tracy
{

struct RPMallocInit
{
    RPMallocInit() { rpmalloc_initialize(); }
};

struct RPMallocThreadInit
{
    RPMallocThreadInit() { rpmalloc_thread_initialize(); }
};

struct InitTimeWrapper
{
    int64_t val;
};

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
#elif defined __ANDROID__
#  if __ANDROID_API__ >= 21
    auto buf = getprogname();
    if( buf ) return buf;
#  endif
#elif defined _GNU_SOURCE || defined __CYGWIN__
    return program_invocation_short_name;
#endif
    return "unknown";
}

enum { QueuePrealloc = 256 * 1024 };

// MSVC static initialization order solution. gcc/clang uses init_order() to avoid all this.

static Profiler* s_instance = nullptr;
static Thread* s_thread = nullptr;

// 1a. But s_queue is needed for initialization of variables in point 2.
extern moodycamel::ConcurrentQueue<QueueItem> s_queue;

static thread_local RPMallocThreadInit init_order(106) s_rpmalloc_thread_init;

// 2. If these variables would be in the .CRT$XCB section, they would be initialized only in main thread.
static thread_local moodycamel::ProducerToken init_order(107) s_token_detail( s_queue );
thread_local ProducerWrapper init_order(108) s_token { s_queue.get_explicit_producer( s_token_detail ) };

#ifdef _MSC_VER
// 1. Initialize these static variables before all other variables.
#  pragma warning( disable : 4075 )
#  pragma init_seg( ".CRT$XCB" )
#endif

static InitTimeWrapper init_order(101) s_initTime { Profiler::GetTime() };
static RPMallocInit init_order(102) s_rpmalloc_init;
moodycamel::ConcurrentQueue<QueueItem> init_order(103) s_queue( QueuePrealloc );
std::atomic<uint32_t> init_order(104) s_lockCounter( 0 );

#ifdef TRACY_COLLECT_THREAD_NAMES
struct ThreadNameData;
std::atomic<ThreadNameData*> init_order(104) s_threadNameData( nullptr );
#endif

static Profiler init_order(105) s_profiler;


enum { BulkSize = TargetFrameSize / QueueItemSize };

Profiler::Profiler()
    : m_timeBegin( 0 )
    , m_mainThread( GetThreadHandle() )
    , m_epoch( std::chrono::duration_cast<std::chrono::seconds>( std::chrono::system_clock::now().time_since_epoch() ).count() )
    , m_shutdown( false )
    , m_sock( nullptr )
    , m_stream( LZ4_createStream() )
    , m_buffer( (char*)tracy_malloc( TargetFrameSize*3 ) )
    , m_bufferOffset( 0 )
    , m_bufferStart( 0 )
    , m_itemBuf( (QueueItem*)tracy_malloc( sizeof( QueueItem ) * BulkSize ) )
    , m_lz4Buf( (char*)tracy_malloc( LZ4Size + sizeof( lz4sz_t ) ) )
{
    assert( !s_instance );
    s_instance = this;

#ifdef _MSC_VER
    // 3. But these variables need to be initialized in main thread within the .CRT$XCB section. Do it here.
    s_token_detail = moodycamel::ProducerToken( s_queue );
    s_token = ProducerWrapper { s_queue.get_explicit_producer( s_token_detail ) };
#endif

    CalibrateTimer();
    CalibrateDelay();

    s_thread = (Thread*)tracy_malloc( sizeof( Thread ) );
    new(s_thread) Thread( LaunchWorker, this );
    SetThreadName( s_thread->Handle(), "Tracy Profiler" );

    m_timeBegin.store( GetTime(), std::memory_order_relaxed );
}

Profiler::~Profiler()
{
    m_shutdown.store( true, std::memory_order_relaxed );
    s_thread->~Thread();
    tracy_free( s_thread );

    tracy_free( m_lz4Buf );
    tracy_free( m_itemBuf );
    tracy_free( m_buffer );
    LZ4_freeStream( m_stream );

    if( m_sock )
    {
        m_sock->~Socket();
        tracy_free( m_sock );
    }

    assert( s_instance );
    s_instance = nullptr;
}

bool Profiler::ShouldExit()
{
    return s_instance->m_shutdown.load( std::memory_order_relaxed );
}

void Profiler::Worker()
{
    rpmalloc_thread_initialize();

    const auto procname = GetProcessName();
    const auto pnsz = std::min<size_t>( strlen( procname ), WelcomeMessageProgramNameSize - 1 );

    while( m_timeBegin.load( std::memory_order_relaxed ) == 0 ) std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );

    WelcomeMessage welcome;
    welcome.timerMul = m_timerMul;
    welcome.initBegin = s_initTime.val;
    welcome.initEnd = m_timeBegin.load( std::memory_order_relaxed );
    welcome.delay = m_delay;
    welcome.resolution = m_resolution;
    welcome.epoch = m_epoch;
    memcpy( welcome.programName, procname, pnsz );
    memset( welcome.programName + pnsz, 0, WelcomeMessageProgramNameSize - pnsz );

    moodycamel::ConsumerToken token( s_queue );

    ListenSocket listen;
    listen.Listen( "8086", 8 );

    for(;;)
    {
        for(;;)
        {
#ifndef TRACY_NO_EXIT
            if( ShouldExit() ) return;
#endif
            m_sock = listen.Accept();
            if( m_sock ) break;
        }

        m_sock->Send( &welcome, sizeof( welcome ) );
        LZ4_resetStream( m_stream );

        for(;;)
        {
            const auto status = Dequeue( token );
            if( status == ConnectionLost )
            {
                break;
            }
            else if( status == QueueEmpty )
            {
                if( ShouldExit() ) break;
                if( m_bufferOffset != m_bufferStart ) CommitData();
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }

            while( m_sock->HasData() )
            {
                if( !HandleServerQuery() ) break;
            }
        }
        if( ShouldExit() ) break;
    }

    QueueItem terminate;
    terminate.hdr.type = QueueType::Terminate;
    if( !SendData( (const char*)&terminate, 1 ) ) return;
    for(;;)
    {
        if( m_sock->HasData() )
        {
            while( m_sock->HasData() )
            {
                if( !HandleServerQuery() )
                {
                    if( m_bufferOffset != m_bufferStart ) CommitData();
                    return;
                }
            }
            while( Dequeue( token ) == Success ) {}
            if( m_bufferOffset != m_bufferStart )
            {
                if( !CommitData() ) return;
            }
        }
        else
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
        }
    }
}

Profiler::DequeueStatus Profiler::Dequeue( moodycamel::ConsumerToken& token )
{
    const auto sz = s_queue.try_dequeue_bulk( token, m_itemBuf, BulkSize );
    if( sz > 0 )
    {
        for( size_t i=0; i<sz; i++ )
        {
            if( !AppendData( m_itemBuf+i, QueueDataSize[m_itemBuf[i].hdr.idx] ) ) return ConnectionLost;
        }
    }
    else
    {
        return QueueEmpty;
    }
    return Success;
}

bool Profiler::AppendData( const void* data, size_t len )
{
    auto ret = true;
    if( m_bufferOffset - m_bufferStart + len > TargetFrameSize ) ret = CommitData();
    memcpy( m_buffer + m_bufferOffset, data, len );
    m_bufferOffset += len;
    return ret;
}

bool Profiler::CommitData()
{
    bool ret = SendData( m_buffer + m_bufferStart, m_bufferOffset - m_bufferStart );
    if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;
    m_bufferStart = m_bufferOffset;
    return ret;
}

bool Profiler::SendData( const char* data, size_t len )
{
    const lz4sz_t lz4sz = LZ4_compress_fast_continue( m_stream, data, m_lz4Buf + sizeof( lz4sz_t ), (int)len, LZ4Size, 1 );
    memcpy( m_lz4Buf, &lz4sz, sizeof( lz4sz ) );
    return m_sock->Send( m_lz4Buf, lz4sz + sizeof( lz4sz_t ) ) != -1;
}

bool Profiler::SendString( uint64_t str, const char* ptr, QueueType type )
{
    assert( type == QueueType::StringData || type == QueueType::ThreadName || type == QueueType::CustomStringData || type == QueueType::PlotName || type == QueueType::MessageData );

    QueueItem item;
    item.hdr.type = type;
    item.stringTransfer.ptr = str;
    AppendData( &item, QueueDataSize[item.hdr.idx] );

    auto len = strlen( ptr );
    assert( len <= std::numeric_limits<uint16_t>::max() );
    auto l16 = uint16_t( len );
    AppendData( &l16, sizeof( l16 ) );
    AppendData( ptr, l16 );

    return true;
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

bool Profiler::SendSourceLocationPayload( uint64_t _ptr )
{
    auto ptr = (const char*)_ptr;

    QueueItem item;
    item.hdr.type = QueueType::SourceLocationPayload;
    item.stringTransfer.ptr = _ptr;
    AppendData( &item, QueueDataSize[item.hdr.idx] );

    const auto len = *((uint32_t*)ptr);
    assert( len <= std::numeric_limits<uint16_t>::max() );
    assert( len > 4 );
    const auto l16 = uint16_t( len - 4 );
    AppendData( &l16, sizeof( l16 ) );
    AppendData( ptr + 4, l16 );

    return true;
}

static bool DontExit() { return false; }

bool Profiler::HandleServerQuery()
{
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    uint8_t type;
    if( !m_sock->Read( &type, sizeof( type ), &tv, DontExit ) ) return false;

    uint64_t ptr;
    if( !m_sock->Read( &ptr, sizeof( ptr ), &tv, DontExit ) ) return false;

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
        tracy_free( (void*)ptr );
        break;
    case ServerQuerySourceLocation:
        SendSourceLocation( ptr );
        break;
    case ServerQuerySourceLocationPayload:
        SendSourceLocationPayload( ptr );
        tracy_free( (void*)ptr );
        break;
    case ServerQueryPlotName:
        SendString( ptr, (const char*)ptr, QueueType::PlotName );
        break;
    case ServerQueryMessage:
        SendString( ptr, (const char*)ptr, QueueType::MessageData );
        tracy_free( (void*)ptr );
        break;
    case ServerQueryTerminate:
        return false;
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
    const auto f0 = GetTime();
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocation __tracy_source_location { __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 };
        FakeZone ___tracy_scoped_zone( &__tracy_source_location );
    }
    const auto t0 = GetTime();
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
    const auto t1 = GetTime();
    const auto dt = t1 - t0;
    const auto df = t0 - f0;
    m_delay = ( dt - df ) / Events;

    auto mindiff = std::numeric_limits<int64_t>::max();
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
        left -= (int)sz;
    }
}

}

#endif
