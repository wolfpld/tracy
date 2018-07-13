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
#include <mutex>
#include <stdlib.h>
#include <string.h>

#include "../common/TracyAlign.hpp"
#include "../common/TracyProtocol.hpp"
#include "../common/TracySocket.hpp"
#include "../common/TracySystem.hpp"
#include "tracy_rpmalloc.hpp"
#include "TracyCallstack.hpp"
#include "TracyScoped.hpp"
#include "TracyProfiler.hpp"
#include "TracyThread.hpp"

#ifdef __GNUC__
#define init_order( val ) __attribute__ ((init_priority(val)))
#else
#define init_order(x)
#endif

#if defined TRACY_HW_TIMER && __ARM_ARCH >= 6
#  include <signal.h>
#  include <setjmp.h>
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

#if defined TRACY_HW_TIMER && __ARM_ARCH >= 6
int64_t (*GetTimeImpl)();

int64_t GetTimeImplFallback()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
}

int64_t GetTimeImplCntvct()
{
    int64_t t;
#  ifdef __aarch64__
    asm volatile ( "mrs %0, cntvct_el0" : "=r" (t) );
#  else
    asm volatile ( "mrrc p15, 1, %Q0, %R0, c14" : "=r" (t) );
#  endif
    return t;
}

static sigjmp_buf SigIllEnv;

static int SetupHwTimerFailed()
{
    return sigsetjmp( SigIllEnv, 1 );
}

static void SetupHwTimerSigIllHandler( int signum )
{
    siglongjmp( SigIllEnv, 1 );
}

static int64_t SetupHwTimer()
{
    struct sigaction act, oldact;
    memset( &act, 0, sizeof( act ) );
    act.sa_handler = SetupHwTimerSigIllHandler;

    if( sigaction( SIGILL, &act, &oldact ) )
    {
        GetTimeImpl = GetTimeImplFallback;
        return Profiler::GetTime();
    }

    if( SetupHwTimerFailed() )
    {
        sigaction( SIGILL, &oldact, nullptr );
        GetTimeImpl = GetTimeImplFallback;
        return Profiler::GetTime();
    }

    GetTimeImplCntvct();

    sigaction( SIGILL, &oldact, nullptr );
    GetTimeImpl = GetTimeImplCntvct;
    return Profiler::GetTime();
}
#else
static int64_t SetupHwTimer()
{
    return Profiler::GetTime();
}
#endif

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

static InitTimeWrapper init_order(101) s_initTime { SetupHwTimer() };
static RPMallocInit init_order(102) s_rpmalloc_init;
moodycamel::ConcurrentQueue<QueueItem> init_order(103) s_queue( QueuePrealloc );
std::atomic<uint32_t> init_order(104) s_lockCounter( 0 );
std::atomic<uint8_t> init_order(104) s_gpuCtxCounter( 0 );

thread_local GpuCtxWrapper init_order(104) s_gpuCtx { nullptr };
VkCtxWrapper init_order(104) s_vkCtx { nullptr };

#ifdef TRACY_COLLECT_THREAD_NAMES
struct ThreadNameData;
std::atomic<ThreadNameData*> init_order(104) s_threadNameData( nullptr );
#endif

#ifdef TRACY_ON_DEMAND
thread_local LuaZoneState init_order(104) s_luaZoneState { 0, false };
#endif

Profiler init_order(105) s_profiler;


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
    , m_serialQueue( 1024*1024 )
    , m_serialDequeue( 1024*1024 )
#ifdef TRACY_ON_DEMAND
    , m_isConnected( false )
    , m_frameCount( 0 )
    , m_deferredQueue( 64*1024 )
#endif
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

#ifdef TRACY_HAS_CALLSTACK
    InitCallstack();
#endif

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

#ifdef TRACY_ON_DEMAND
    uint8_t onDemand = 1;
#else
    uint8_t onDemand = 0;
#endif

    WelcomeMessage welcome;
    MemWrite( &welcome.timerMul, m_timerMul );
    MemWrite( &welcome.initBegin, s_initTime.val );
    MemWrite( &welcome.initEnd, m_timeBegin.load( std::memory_order_relaxed ) );
    MemWrite( &welcome.delay, m_delay );
    MemWrite( &welcome.resolution, m_resolution );
    MemWrite( &welcome.epoch, m_epoch );
    MemWrite( &welcome.onDemand, onDemand );
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

#ifdef TRACY_ON_DEMAND
        ClearQueues( token );
        m_isConnected.store( true, std::memory_order_relaxed );
#endif

        LZ4_resetStream( m_stream );
        m_sock->Send( &welcome, sizeof( welcome ) );

#ifdef TRACY_ON_DEMAND
        OnDemandPayloadMessage onDemand;
        onDemand.frames = m_frameCount.load( std::memory_order_relaxed );

        m_sock->Send( &onDemand, sizeof( onDemand ) );

        m_deferredLock.lock();
        for( auto& item : m_deferredQueue )
        {
            const auto idx = MemRead<uint8_t>( &item.hdr.idx );
            AppendData( &item, QueueDataSize[idx] );
        }
        m_deferredLock.unlock();
#endif

        int keepAlive = 0;
        for(;;)
        {
            const auto status = Dequeue( token );
            const auto serialStatus = DequeueSerial();
            if( status == ConnectionLost || serialStatus == ConnectionLost )
            {
                break;
            }
            else if( status == QueueEmpty && serialStatus == QueueEmpty )
            {
                if( ShouldExit() ) break;
                if( m_bufferOffset != m_bufferStart )
                {
                    if( !CommitData() ) break;
                }
                if( keepAlive == 500 )
                {
                    QueueItem ka;
                    ka.hdr.type = QueueType::KeepAlive;
                    AppendData( &ka, QueueDataSize[ka.hdr.idx] );
                    if( !CommitData() ) break;

                    keepAlive = 0;
                }
                else
                {
                    keepAlive++;
                    std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
                }
            }
            else
            {
                keepAlive = 0;
            }

            while( m_sock->HasData() )
            {
                if( !HandleServerQuery() ) break;
            }
        }
        if( ShouldExit() ) break;

#ifdef TRACY_ON_DEMAND
        m_isConnected.store( false, std::memory_order_relaxed );
#endif
    }

    for(;;)
    {
        const auto status = Dequeue( token );
        const auto serialStatus = DequeueSerial();
        if( status == ConnectionLost || serialStatus == ConnectionLost )
        {
            break;
        }
        else if( status == QueueEmpty && serialStatus == QueueEmpty )
        {
            if( m_bufferOffset != m_bufferStart ) CommitData();
            break;
        }

        while( m_sock->HasData() )
        {
            if( !HandleServerQuery() ) break;
        }
    }

    QueueItem terminate;
    MemWrite( &terminate.hdr.type, QueueType::Terminate );
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
            while( DequeueSerial() == Success ) {}
            if( m_bufferOffset != m_bufferStart )
            {
                if( !CommitData() ) return;
            }
        }
        else
        {
            if( m_bufferOffset != m_bufferStart ) CommitData();
            std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
        }
    }
}

static void FreeAssociatedMemory( const QueueItem& item )
{
    if( item.hdr.idx >= (int)QueueType::Terminate ) return;

    uint64_t ptr;
    switch( item.hdr.type )
    {
    case QueueType::ZoneText:
    case QueueType::ZoneName:
        ptr = MemRead<uint64_t>( &item.zoneText.text );
        tracy_free( (void*)ptr );
        break;
    case QueueType::Message:
        ptr = MemRead<uint64_t>( &item.message.text );
        tracy_free( (void*)ptr );
        break;
    case QueueType::ZoneBeginAllocSrcLoc:
        ptr = MemRead<uint64_t>( &item.zoneBegin.srcloc );
        tracy_free( (void*)ptr );
        break;
    case QueueType::CallstackMemory:
        ptr = MemRead<uint64_t>( &item.callstackMemory.ptr );
        tracy_free( (void*)ptr );
        break;
    case QueueType::Callstack:
        ptr = MemRead<uint64_t>( &item.callstack.ptr );
        tracy_free( (void*)ptr );
        break;
    default:
        assert( false );
        break;
    }
}

void Profiler::ClearQueues( moodycamel::ConsumerToken& token )
{
    for(;;)
    {
        const auto sz = s_queue.try_dequeue_bulk( token, m_itemBuf, BulkSize );
        if( sz == 0 ) break;
        for( size_t i=0; i<sz; i++ ) FreeAssociatedMemory( m_itemBuf[i] );
    }

    std::lock_guard<NonRecursiveBenaphore> lock( m_serialLock );

    for( auto& v : m_serialDequeue ) FreeAssociatedMemory( v );
    m_serialDequeue.clear();

    for( auto& v : m_serialQueue ) FreeAssociatedMemory( v );
    m_serialQueue.clear();
}

Profiler::DequeueStatus Profiler::Dequeue( moodycamel::ConsumerToken& token )
{
    const auto sz = s_queue.try_dequeue_bulk( token, m_itemBuf, BulkSize );
    if( sz > 0 )
    {
        auto end = m_itemBuf + sz;
        auto item = m_itemBuf;
        while( item != end )
        {
            uint64_t ptr;
            const auto idx = MemRead<uint8_t>( &item->hdr.idx );
            if( idx < (int)QueueType::Terminate )
            {
                switch( (QueueType)idx )
                {
                case QueueType::ZoneText:
                case QueueType::ZoneName:
                    ptr = MemRead<uint64_t>( &item->zoneText.text );
                    SendString( ptr, (const char*)ptr, QueueType::CustomStringData );
                    tracy_free( (void*)ptr );
                    break;
                case QueueType::Message:
                    ptr = MemRead<uint64_t>( &item->message.text );
                    SendString( ptr, (const char*)ptr, QueueType::CustomStringData );
                    tracy_free( (void*)ptr );
                    break;
                case QueueType::ZoneBeginAllocSrcLoc:
                    ptr = MemRead<uint64_t>( &item->zoneBegin.srcloc );
                    SendSourceLocationPayload( ptr );
                    tracy_free( (void*)ptr );
                    break;
                case QueueType::Callstack:
                    ptr = MemRead<uint64_t>( &item->callstack.ptr );
                    SendCallstackPayload( ptr );
                    tracy_free( (void*)ptr );
                    break;
                default:
                    assert( false );
                    break;
                }
            }
            if( !AppendData( item, QueueDataSize[idx] ) ) return ConnectionLost;
            item++;
        }
    }
    else
    {
        return QueueEmpty;
    }
    return Success;
}

Profiler::DequeueStatus Profiler::DequeueSerial()
{
    {
        std::lock_guard<NonRecursiveBenaphore> lock( m_serialLock );
        m_serialQueue.swap( m_serialDequeue );
    }

    const auto sz = m_serialDequeue.size();
    if( sz > 0 )
    {
        auto item = m_serialDequeue.data();
        auto end = item + sz;
        while( item != end )
        {
            uint64_t ptr;
            const auto idx = MemRead<uint8_t>( &item->hdr.idx );
            if( idx < (int)QueueType::Terminate )
            {
                switch( (QueueType)idx )
                {
                case QueueType::CallstackMemory:
                    ptr = MemRead<uint64_t>( &item->callstackMemory.ptr );
                    SendCallstackPayload( ptr );
                    tracy_free( (void*)ptr );
                    break;
                default:
                    assert( false );
                    break;
                }
            }
            if( !AppendData( item, QueueDataSize[idx] ) ) return ConnectionLost;
            item++;
        }
        m_serialDequeue.clear();
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
    ret = NeedDataSize( len );
    AppendDataUnsafe( data, len );
    return ret;
}

bool Profiler::CommitData()
{
    bool ret = SendData( m_buffer + m_bufferStart, m_bufferOffset - m_bufferStart );
    if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;
    m_bufferStart = m_bufferOffset;
    return ret;
}

bool Profiler::NeedDataSize( size_t len )
{
    bool ret = true;
    if( m_bufferOffset - m_bufferStart + len > TargetFrameSize )
    {
        ret = CommitData();
    }
    return ret;
}

bool Profiler::SendData( const char* data, size_t len )
{
    const lz4sz_t lz4sz = LZ4_compress_fast_continue( m_stream, data, m_lz4Buf + sizeof( lz4sz_t ), (int)len, LZ4Size, 1 );
    memcpy( m_lz4Buf, &lz4sz, sizeof( lz4sz ) );
    return m_sock->Send( m_lz4Buf, lz4sz + sizeof( lz4sz_t ) ) != -1;
}

void Profiler::SendString( uint64_t str, const char* ptr, QueueType type )
{
    assert( type == QueueType::StringData || type == QueueType::ThreadName || type == QueueType::CustomStringData || type == QueueType::PlotName );

    QueueItem item;
    MemWrite( &item.hdr.type, type );
    MemWrite( &item.stringTransfer.ptr, str );

    auto len = strlen( ptr );
    assert( len <= std::numeric_limits<uint16_t>::max() );
    auto l16 = uint16_t( len );

    NeedDataSize( QueueDataSize[(int)type] + sizeof( l16 ) + l16 );

    AppendDataUnsafe( &item, QueueDataSize[(int)type] );
    AppendDataUnsafe( &l16, sizeof( l16 ) );
    AppendDataUnsafe( ptr, l16 );
}

void Profiler::SendSourceLocation( uint64_t ptr )
{
    auto srcloc = (const SourceLocation*)ptr;
    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::SourceLocation );
    MemWrite( &item.srcloc.name, (uint64_t)srcloc->name );
    MemWrite( &item.srcloc.file, (uint64_t)srcloc->file );
    MemWrite( &item.srcloc.function, (uint64_t)srcloc->function );
    MemWrite( &item.srcloc.line, srcloc->line );
    MemWrite( &item.srcloc.r, uint8_t( ( srcloc->color       ) & 0xFF ) );
    MemWrite( &item.srcloc.g, uint8_t( ( srcloc->color >> 8  ) & 0xFF ) );
    MemWrite( &item.srcloc.b, uint8_t( ( srcloc->color >> 16 ) & 0xFF ) );
    AppendData( &item, QueueDataSize[(int)QueueType::SourceLocation] );
}

void Profiler::SendSourceLocationPayload( uint64_t _ptr )
{
    auto ptr = (const char*)_ptr;

    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::SourceLocationPayload );
    MemWrite( &item.stringTransfer.ptr, _ptr );

    const auto len = *((uint32_t*)ptr);
    assert( len <= std::numeric_limits<uint16_t>::max() );
    assert( len > 4 );
    const auto l16 = uint16_t( len - 4 );

    NeedDataSize( QueueDataSize[(int)QueueType::SourceLocationPayload] + sizeof( l16 ) + l16 );

    AppendDataUnsafe( &item, QueueDataSize[(int)QueueType::SourceLocationPayload] );
    AppendDataUnsafe( &l16, sizeof( l16 ) );
    AppendDataUnsafe( ptr + 4, l16 );
}

void Profiler::SendCallstackPayload( uint64_t _ptr )
{
    auto ptr = (uintptr_t*)_ptr;

    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::CallstackPayload );
    MemWrite( &item.stringTransfer.ptr, _ptr );

    const auto sz = *ptr++;
    const auto len = sz * sizeof( uint64_t );
    const auto l16 = uint16_t( len );

    NeedDataSize( QueueDataSize[(int)QueueType::CallstackPayload] + sizeof( l16 ) + l16 );

    AppendDataUnsafe( &item, QueueDataSize[(int)QueueType::CallstackPayload] );
    AppendDataUnsafe( &l16, sizeof( l16 ) );

    if( sizeof( uintptr_t ) == sizeof( uint64_t ) )
    {
        AppendDataUnsafe( ptr, sizeof( uint64_t ) * sz );
    }
    else
    {
        for( uintptr_t i=0; i<sz; i++ )
        {
            const auto val = uint64_t( *ptr++ );
            AppendDataUnsafe( &val, sizeof( uint64_t ) );
        }
    }
}

void Profiler::SendCallstackFrame( uint64_t ptr )
{
#ifdef TRACY_HAS_CALLSTACK
    auto frame = DecodeCallstackPtr( ptr );

    SendString( uint64_t( frame.name ), frame.name, QueueType::CustomStringData );
    SendString( uint64_t( frame.file ), frame.file, QueueType::CustomStringData );

    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::CallstackFrame );
    MemWrite( &item.callstackFrame.ptr, ptr );
    MemWrite( &item.callstackFrame.name, (uint64_t)frame.name );
    MemWrite( &item.callstackFrame.file, (uint64_t)frame.file );
    MemWrite( &item.callstackFrame.line, frame.line );

    AppendData( &item, QueueDataSize[(int)QueueType::CallstackFrame] );

    tracy_free( (void*)frame.name );
    tracy_free( (void*)frame.file );
#endif
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
    case ServerQuerySourceLocation:
        SendSourceLocation( ptr );
        break;
    case ServerQueryPlotName:
        SendString( ptr, (const char*)ptr, QueueType::PlotName );
        break;
    case ServerQueryTerminate:
        return false;
    case ServerQueryCallstackFrame:
        SendCallstackFrame( ptr );
        break;
    default:
        assert( false );
        break;
    }

    return true;
}

void Profiler::CalibrateTimer()
{
#ifdef TRACY_HW_TIMER
#  if __ARM_ARCH >= 6
    if( GetTimeImpl == GetTimeImplFallback )
    {
        m_timerMul = 1.;
        return;
    }
#  endif

    std::atomic_signal_fence( std::memory_order_acq_rel );
    const auto t0 = std::chrono::high_resolution_clock::now();
    const auto r0 = GetTime();
    std::atomic_signal_fence( std::memory_order_acq_rel );
    std::this_thread::sleep_for( std::chrono::milliseconds( 200 ) );
    std::atomic_signal_fence( std::memory_order_acq_rel );
    const auto t1 = std::chrono::high_resolution_clock::now();
    const auto r1 = GetTime();
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
        static const tracy::SourceLocation __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 };
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::ZoneBegin );
            MemWrite( &item->zoneBegin.thread, GetThreadHandle() );
#ifdef TRACY_RDTSCP_OPT
            MemWrite( &item->zoneBegin.time, Profiler::GetTime( item->zoneBegin.cpu ) );
#else
            uint32_t cpu;
            MemWrite( &item->zoneBegin.time, Profiler::GetTime( cpu ) );
            MemWrite( &item->zoneBegin.cpu, cpu );
#endif
            MemWrite( &item->zoneBegin.srcloc, (uint64_t)&__tracy_source_location );
            tail.store( magic + 1, std::memory_order_release );
        }
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::ZoneEnd );
            MemWrite( &item->zoneEnd.thread, uint64_t( 0 ) );
#ifdef TRACY_RDTSCP_OPT
            MemWrite( &item->zoneEnd.time, GetTime( item->zoneEnd.cpu ) );
#else
            uint32_t cpu;
            MemWrite( &item->zoneEnd.time, GetTime( cpu ) );
            MemWrite( &item->zoneEnd.cpu, cpu );
#endif
            tail.store( magic + 1, std::memory_order_release );
        }
    }
    const auto f0 = GetTime();
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocation __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 };
        FakeZone ___tracy_scoped_zone( &__tracy_source_location );
    }
    const auto t0 = GetTime();
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocation __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 };
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::ZoneBegin );
            MemWrite( &item->zoneBegin.thread, GetThreadHandle() );
#ifdef TRACY_RDTSCP_OPT
            MemWrite( &item->zoneBegin.time, Profiler::GetTime( item->zoneBegin.cpu ) );
#else
            uint32_t cpu;
            MemWrite( &item->zoneBegin.time, Profiler::GetTime( cpu ) );
            MemWrite( &item->zoneBegin.cpu, cpu );
#endif
            MemWrite( &item->zoneBegin.srcloc, (uint64_t)&__tracy_source_location );
            tail.store( magic + 1, std::memory_order_release );
        }
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::ZoneEnd );
            MemWrite( &item->zoneEnd.thread, uint64_t( 0 ) );
#ifdef TRACY_RDTSCP_OPT
            MemWrite( &item->zoneEnd.time, GetTime( item->zoneEnd.cpu ) );
#else
            uint32_t cpu;
            MemWrite( &item->zoneEnd.time, GetTime( cpu ) );
            MemWrite( &item->zoneEnd.cpu, cpu );
#endif
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
        const auto t0i = GetTime();
        const auto t1i = GetTime();
        const auto dti = t1i - t0i;
        if( dti > 0 && dti < mindiff ) mindiff = dti;
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
