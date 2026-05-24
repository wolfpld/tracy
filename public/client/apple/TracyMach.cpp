// (this file gets included by TracySysTrace.cpp)

#ifndef __APPLE__
#error this file can only be compiled for Apple targets
#endif

#include <atomic>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <ptrauth.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "../TracyProfiler.hpp"
#include "../TracyStringHelpers.hpp"
#include "../TracyThread.hpp"

namespace tracy
{

struct SysTraceApple
{
    std::atomic<bool> active { false };
    int samplingHz = 1000;
    static SysTraceApple& Get()
    {
        static SysTraceApple systrace = {};
        return systrace;
    }
};

static void SysTraceEmitCallstackSample( uint32_t threadId, int64_t timestamp, const uint64_t* frames, int depth )
{
#ifdef TRACY_ON_DEMAND
    if( !GetProfiler().IsConnected() ) return;
#endif

    auto trace = (uint64_t*)tracy_malloc( ( 1 + depth ) * sizeof( uint64_t ) );
    trace[0] = (uint64_t)depth;
    memcpy( trace + 1, frames, depth * sizeof( uint64_t ) );

    TracyLfqPrepare( QueueType::CallstackSample );
    MemWrite( &item->callstackSampleFat.time, timestamp );
    MemWrite( &item->callstackSampleFat.thread, threadId );
    MemWrite( &item->callstackSampleFat.ptr, (uint64_t)trace );
    TracyLfqCommit;
}

static int SysTraceBacktrace( uint64_t* frames, int maxDepth, uint64_t pc, uint64_t fp )
{
    int depth = 0;
    frames[depth++] = pc;

    // NOTE: frame-pointer walk for now... It should be fine since the ABI
    // mandates it on ARM64 (and on x64 Apple clang preserves it by default)
    auto framePtr = (const uint64_t*)fp;
    while( framePtr && depth < maxDepth )
    {
        if( (uintptr_t)framePtr & (sizeof(uint64_t) - 1) ) break;  // misaligned — stop walk
        // [framePtr + 0] = saved frame pointer (previous frame)
        // [framePtr + 1] = return address, may be PAC-signed on ARM64
        frames[depth++] = (uint64_t)ptrauth_strip( (void*)framePtr[1], ptrauth_key_return_address );
        framePtr = (const uint64_t*)framePtr[0];
    }

    return depth;
}

static void SysTraceSampleThread( mach_port_t tid )
{
    const int64_t t0 = Profiler::GetTime();
    if( thread_suspend( tid ) != KERN_SUCCESS ) return;
    const int64_t t1 = Profiler::GetTime();
    const int64_t timestamp = t0 + ( t1 - t0 ) / 2;

#if defined(__aarch64__)
    arm_thread_state64_t state;
    mach_msg_type_number_t stateCount = ARM_THREAD_STATE64_COUNT;
    const kern_return_t kr = thread_get_state( tid, ARM_THREAD_STATE64, (thread_state_t)&state, &stateCount );
#elif defined(__x86_64__)
    x86_thread_state64_t state;
    mach_msg_type_number_t stateCount = x86_THREAD_STATE64_COUNT;
    const kern_return_t kr = thread_get_state( tid, x86_THREAD_STATE64, (thread_state_t)&state, &stateCount );
#else
    #error "unsupported architecture"
#endif

    if( kr != KERN_SUCCESS )
    {
        thread_resume( tid );
        return;
    }

    constexpr int MaxDepth = 192;
    uint64_t frames [MaxDepth];

#if defined(__aarch64__)
    const int depth = SysTraceBacktrace( frames, MaxDepth, state.__pc, state.__fp );
#elif defined(__x86_64__)
    const int depth = SysTraceBacktrace( frames, MaxDepth, state.__rip, state.__rbp );
#endif

    thread_resume( tid );

    SysTraceEmitCallstackSample( (uint32_t)tid, timestamp, frames, depth );
}

static void SysTraceWait( uint64_t deadline )
{
    mach_wait_until( deadline );
}

static uint64_t SysTraceRngInit()
{
    uint64_t seed = mach_absolute_time();
    seed ^= (uint64_t)(uintptr_t)&seed;
    return seed;
}

static uint32_t SysTraceRngNext( uint64_t& rng, uint32_t range )
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return (uint32_t)( rng % range );
}

static void SysTraceWatch()
{
    auto& systrace = SysTraceApple::Get();

    const mach_port_t selfThread = mach_thread_self();
    mach_timebase_info_data_t timebase;
    mach_timebase_info( &timebase );
    const uint64_t samplingPeriodNs = 1000000000ULL / systrace.samplingHz;
    const uint64_t periodMach = samplingPeriodNs * timebase.denom / timebase.numer;

    std::vector<mach_port_t> runningThreads;
    std::vector<mach_port_t> waitingThreads;

    uint64_t rng = SysTraceRngInit();

    uint64_t deadline = mach_absolute_time();
    while( systrace.active.load( std::memory_order_relaxed ) )
    {
        SysTraceWait(deadline);
        deadline = mach_absolute_time() + periodMach;

#ifdef TRACY_ON_DEMAND
        if( !GetProfiler().IsConnected() ) continue;
#endif

        thread_act_array_t threads;
        mach_msg_type_number_t threadCount;
        if( task_threads( mach_task_self(), &threads, &threadCount ) != KERN_SUCCESS ) continue;

        runningThreads.clear();
        waitingThreads.clear();

        for( mach_msg_type_number_t i = 0; i < threadCount; i++ )
        {
            const mach_port_t tid = threads[i];
            if( tid == selfThread ) continue;

            thread_basic_info_data_t info;
            mach_msg_type_number_t infoCount = THREAD_BASIC_INFO_COUNT;
            if( thread_info( tid, THREAD_BASIC_INFO, (thread_info_t)&info, &infoCount ) != KERN_SUCCESS ) continue;
            if( info.flags & TH_FLAGS_IDLE ) continue;  // kernel idle thread, not user code

            if( info.run_state == TH_STATE_RUNNING )
                runningThreads.push_back( tid );
            else
                waitingThreads.push_back( tid );
        }

        for( const mach_port_t tid : runningThreads )
            SysTraceSampleThread( tid );

        while( !waitingThreads.empty() )
        {
            if( mach_absolute_time() >= deadline ) break;
            const uint32_t idx = SysTraceRngNext( rng, (uint32_t)waitingThreads.size() );
            SysTraceSampleThread( waitingThreads[idx] );
            std::swap( waitingThreads[idx], waitingThreads.back() );
            waitingThreads.pop_back();
        }

        for( mach_msg_type_number_t i = 0; i < threadCount; i++ )
            mach_port_deallocate( mach_task_self(), threads[i] );
        vm_deallocate( mach_task_self(), (vm_address_t)threads, sizeof(thread_t) * threadCount );
    }
    mach_port_deallocate( mach_task_self(), selfThread );
}

void SysTraceWorker( void* )
{
    ThreadExitHandler threadExitHandler;
    SetThreadName( "Tracy Mach Watchdog" );
    InitAllocator();
    SysTraceWatch();
}

bool SysTraceStart( int64_t& samplingPeriod )
{
    // check for elevated privileges
    // (technically, since this is a software-based user-mode sampling, elevated
    // privileges are unnecessary, but doing so keeps the behavior consistent with
    // the system tracing in other platforms)
    if( geteuid() != 0 ) return false;

    auto& systrace = SysTraceApple::Get();

    bool expected = false;
    if( !systrace.active.compare_exchange_strong( expected, true, std::memory_order_relaxed ) )
        return false;

    systrace.samplingHz = GetSamplingFrequency();
    samplingPeriod      = SamplingFrequencyToPeriodNs( systrace.samplingHz );
    return true;
}

void SysTraceStop()
{
    auto& systrace = SysTraceApple::Get();
    systrace.active.store( false, std::memory_order_relaxed );
}

void SysTraceGetExternalName( uint64_t thread, const char*& threadName, const char*& name )
{
    // Resolve pthread handle from the Mach port so we can query the thread name.
    const mach_port_t mach_tid = (mach_port_t)thread;
    thread_identifier_info_data_t idInfo;
    mach_msg_type_number_t idInfoCount = THREAD_IDENTIFIER_INFO_COUNT;
    if( thread_info( mach_tid, THREAD_IDENTIFIER_INFO, (thread_info_t)&idInfo, &idInfoCount ) == KERN_SUCCESS )
    {
        char buf[64] = {};
        const pthread_t pt = (pthread_t)(uintptr_t)idInfo.thread_handle;
        if( pt && pthread_getname_np( pt, buf, sizeof( buf ) ) == 0 && buf[0] != '\0' )
            threadName = CopyString( buf );
        else
            threadName = CopyString( "???", 3 );

        TracyLfqPrepare( QueueType::TidToPid );
        MemWrite( &item->tidToPid.tid, thread );
        MemWrite( &item->tidToPid.pid, (uint64_t)getpid() );
        TracyLfqCommit;
    }
    else
    {
        threadName = CopyString( "???", 3 );
    }

    name = CopyStringFast( getprogname() );
}

} // namespace tracy
