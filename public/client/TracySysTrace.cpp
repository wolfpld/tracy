#include "TracyDebug.hpp"
#include "TracyStringHelpers.hpp"
#include "TracySysTrace.hpp"
#include "../common/TracySystem.hpp"

#ifdef TRACY_HAS_SYSTEM_TRACING

#ifndef TRACY_SAMPLING_HZ
#  if defined _WIN32
#    define TRACY_SAMPLING_HZ 8000
#  elif defined __linux__
#    define TRACY_SAMPLING_HZ 10000
#  elif defined __APPLE__
#    define TRACY_SAMPLING_HZ 1000
#  endif
#endif

namespace tracy
{

static int GetSamplingFrequency()
{
    int samplingHz = TRACY_SAMPLING_HZ;

    auto env = GetEnvVar( "TRACY_SAMPLING_HZ" );
    if( env )
    {
        int val = atoi( env );
        if( val > 0 ) samplingHz = val;
    }

#if defined _WIN32
    return samplingHz > 8000 ? 8000 : ( samplingHz < 1 ? 1 : samplingHz );
#else
    return samplingHz > 1000000 ? 1000000 : ( samplingHz < 1 ? 1 : samplingHz );
#endif
}

static int SamplingFrequencyToPeriodNs( int samplingHz )
{
    return 1000000000 / samplingHz;
}

}

#  if defined _WIN32

#    ifndef NOMINMAX
#      define NOMINMAX
#    endif

#    define INITGUID
#    include <assert.h>
#    include <string.h>
#    include <windows.h>
#    include <dbghelp.h>
#    include <psapi.h>
#    include <winternl.h>

#    include "../common/TracyAlloc.hpp"
#    include "../common/TracySystem.hpp"
#    include "TracyProfiler.hpp"
#    include "TracyThread.hpp"
#    include "windows/TracyETW_compat.h"
#    include "windows/TracyETW.cpp"

namespace tracy
{

static DWORD s_pid;

extern "C" typedef NTSTATUS (WINAPI *t_NtQueryInformationThread)( HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG );
extern "C" typedef BOOL (WINAPI *t_EnumProcessModules)( HANDLE, HMODULE*, DWORD, LPDWORD );
extern "C" typedef BOOL (WINAPI *t_GetModuleInformation)( HANDLE, HMODULE, LPMODULEINFO, DWORD );
extern "C" typedef DWORD (WINAPI *t_GetModuleBaseNameA)( HANDLE, HMODULE, LPSTR, DWORD );
extern "C" typedef HRESULT (WINAPI *t_GetThreadDescription)( HANDLE, PWSTR* );

t_NtQueryInformationThread NtQueryInformationThread = (t_NtQueryInformationThread)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtQueryInformationThread" );
t_EnumProcessModules _EnumProcessModules = (t_EnumProcessModules)GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "K32EnumProcessModules" );
t_GetModuleInformation _GetModuleInformation = (t_GetModuleInformation)GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "K32GetModuleInformation" );
t_GetModuleBaseNameA _GetModuleBaseNameA = (t_GetModuleBaseNameA)GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "K32GetModuleBaseNameA" );

static t_GetThreadDescription _GetThreadDescription = 0;


void WINAPI EventRecordCallback( PEVENT_RECORD record )
{
#ifdef TRACY_ON_DEMAND
    if( !GetProfiler().IsConnected() ) return;
#endif

    const auto& hdr = record->EventHeader;
    // WARN: doing a fast switch-match below with the top 32 bits of the GUID
    // (Data1 is the leading 32bit word of the 128bit GUID).
    // Ideally, we should be using 'IsEqualGUID()' inside each case match to be
    // inequivocally sure we are dealing the correct event provider.
    switch( hdr.ProviderId.Data1 )
    {
    case etw::ThreadGuid.Data1:
        if( hdr.EventDescriptor.Opcode == etw::CSwitch::Opcode )
        {
            const auto cswitch = (const etw::CSwitch*)record->UserData;

            TracyLfqPrepare( QueueType::ContextSwitch );
            MemWrite( &item->contextSwitch.time, hdr.TimeStamp.QuadPart );
            MemWrite( &item->contextSwitch.oldThread, cswitch->oldThreadId );
            MemWrite( &item->contextSwitch.newThread, cswitch->newThreadId );
            MemWrite( &item->contextSwitch.cpu, record->BufferContext.ProcessorNumber );
            MemWrite( &item->contextSwitch.oldThreadWaitReason, cswitch->oldThreadWaitReason );
            MemWrite( &item->contextSwitch.oldThreadState, cswitch->oldThreadState );
            MemWrite( &item->contextSwitch.newThreadPriority, cswitch->newThreadPriority );
            MemWrite( &item->contextSwitch.oldThreadPriority, cswitch->oldThreadPriority );
            MemWrite( &item->contextSwitch.previousCState, cswitch->previousCState );
            TracyLfqCommit;
        }
        else if( hdr.EventDescriptor.Opcode == etw::ReadyThread::Opcode )
        {
            const auto rt = (const etw::ReadyThread*)record->UserData;

            TracyLfqPrepare( QueueType::ThreadWakeup );
            MemWrite( &item->threadWakeup.time, hdr.TimeStamp.QuadPart );
            MemWrite( &item->threadWakeup.cpu, record->BufferContext.ProcessorNumber );
            MemWrite( &item->threadWakeup.thread, rt->threadId );
            MemWrite( &item->threadWakeup.adjustReason, rt->adjustReason );
            MemWrite( &item->threadWakeup.adjustIncrement, rt->adjustIncrement );
            TracyLfqCommit;
        }
        else if( hdr.EventDescriptor.Opcode == etw::ThreadStart::Opcode || hdr.EventDescriptor.Opcode == etw::ThreadDCStart::Opcode )
        {
            const auto ti = (const etw::ThreadInfo*)record->UserData;

            uint64_t tid = ti->threadId;
            if( tid == 0 ) return;
            uint64_t pid = ti->processId;
            TracyLfqPrepare( QueueType::TidToPid );
            MemWrite( &item->tidToPid.tid, tid );
            MemWrite( &item->tidToPid.pid, pid );
            TracyLfqCommit;
        }
        break;
    case etw::StackWalkGuid.Data1:
        if( hdr.EventDescriptor.Opcode == etw::StackWalkEvent::Opcode )
        {
            const auto sw = (const etw::StackWalkEvent*)record->UserData;
            if( sw->stackProcess == s_pid )
            {
                const uint64_t sz = ( record->UserDataLength - 16 ) / 8;
                if( sz > 0 )
                {
                    auto trace = (uint64_t*)tracy_malloc( ( 1 + sz ) * sizeof( uint64_t ) );
                    memcpy( trace, &sz, sizeof( uint64_t ) );
                    memcpy( trace+1, sw->stack, sizeof( uint64_t ) * sz );
                    TracyLfqPrepare( QueueType::CallstackSample );
                    MemWrite( &item->callstackSampleFat.time, sw->eventTimeStamp );
                    MemWrite( &item->callstackSampleFat.thread, sw->stackThread );
                    MemWrite( &item->callstackSampleFat.ptr, (uint64_t)trace );
                    TracyLfqCommit;
                }
            }
        }
        break;
    case etw::DxgKrnlGuid.Data1:
        assert( hdr.EventDescriptor.Id == etw::VSyncDPC::EventId );
        {
            const auto vs = (const etw::VSyncDPC*)record->UserData;
            TracyLfqPrepare( QueueType::FrameVsync );
            MemWrite( &item->frameVsync.time, hdr.TimeStamp.QuadPart );
            MemWrite( &item->frameVsync.id, vs->vidPnTargetId );
            TracyLfqCommit;
        }
        break;
    default:
        break;
    }
}

static etw::Session session_kernel = {};
static etw::Session session_vsync = {};
static PROCESSTRACE_HANDLE consumer_kernel = INVALID_PROCESSTRACE_HANDLE;
static PROCESSTRACE_HANDLE consumer_vsync = INVALID_PROCESSTRACE_HANDLE;
static Thread* s_threadVsync = nullptr;

bool SysTraceStart( int64_t& samplingPeriod )
{
    if( !_GetThreadDescription ) _GetThreadDescription = (t_GetThreadDescription)GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "GetThreadDescription" );

    s_pid = GetCurrentProcessId();

    if( !etw::CheckAdminPrivilege() )
        return false;

    session_kernel = etw::StartSingletonKernelLoggerSession( 0 );
    if( session_kernel.handle == 0 )
        return false;

#ifndef TRACY_NO_CONTEXT_SWITCH
    if( etw::EnableProcessAndThreadMonitoring( session_kernel ) != ERROR_SUCCESS )
        return etw::StopSession( session_kernel ), false;
    if( etw::EnableContextSwitchMonitoring( session_kernel ) != ERROR_SUCCESS )
        return etw::StopSession( session_kernel ), false;
#endif


#ifndef TRACY_NO_SAMPLING
    samplingPeriod = SamplingFrequencyToPeriodNs( GetSamplingFrequency() );
    const int microseconds = samplingPeriod / 1000;
    if( etw::EnableCPUProfiling( session_kernel, microseconds ) != ERROR_SUCCESS )
        return etw::StopSession( session_kernel ), false;
#endif

    consumer_kernel = etw::SetupEventConsumer( session_kernel, EventRecordCallback );
    if( consumer_kernel == INVALID_PROCESSTRACE_HANDLE )
        return etw::StopSession( session_kernel ), false;

#ifndef TRACY_NO_VSYNC_CAPTURE
    session_vsync = etw::StartUserSession( "TracyVsync" );
    if( session_vsync.handle != 0 )
    {
        if( etw::EnableVSyncMonitoring( session_vsync ) != ERROR_SUCCESS )
            etw::StopSession( session_vsync );
        else
        {
            consumer_vsync = etw::SetupEventConsumer( session_vsync, EventRecordCallback );
            if( consumer_vsync != INVALID_PROCESSTRACE_HANDLE )
            {
                s_threadVsync = (Thread*)tracy_malloc( sizeof( Thread ) );
                new(s_threadVsync) Thread( [] (void*) {
                    ThreadExitHandler threadExitHandler;
                    SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL );
                    SetThreadName( "Tracy Vsync (ETW)" );
                    etw::EventConsumerLoop( consumer_vsync );
                }, nullptr );
            }
        }
    }
#endif

    return true;
}

void SysTraceStop()
{
    if( s_threadVsync )
    {
        etw::StopEventConsumer( consumer_vsync );
        etw::StopSession( session_vsync );
        s_threadVsync->~Thread();
        tracy_free( s_threadVsync );
    }
    etw::StopEventConsumer( consumer_kernel );
    etw::StopSession( session_kernel );
}

void SysTraceWorker( void* ptr )
{
    ThreadExitHandler threadExitHandler;
    SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL );
    SetThreadName( "Tracy SysTrace (ETW)" );
    etw::EventConsumerLoop( consumer_kernel );
}

void SysTraceGetExternalName( uint64_t thread, const char*& threadName, const char*& name )
{
    bool threadSent = false;
    auto hnd = OpenThread( THREAD_QUERY_INFORMATION, FALSE, DWORD( thread ) );
    if( hnd == 0 )
    {
        hnd = OpenThread( THREAD_QUERY_LIMITED_INFORMATION, FALSE, DWORD( thread ) );
    }
    if( hnd != 0 )
    {
        if( _GetThreadDescription )
        {
            PWSTR tmp;
            if ( SUCCEEDED( _GetThreadDescription( hnd, &tmp ) ) )
            {
                char buf[256];
                auto ret = wcstombs( buf, tmp, 256 );
                LocalFree(tmp);
                if( ret != 0 )
                {
                    threadName = CopyString( buf, ret );
                    threadSent = true;
                }
            }
        }
        const auto pid = GetProcessIdOfThread( hnd );
        if( !threadSent && NtQueryInformationThread && _EnumProcessModules && _GetModuleInformation && _GetModuleBaseNameA )
        {
            void* ptr;
            ULONG retlen;
            auto status = NtQueryInformationThread( hnd, (THREADINFOCLASS)9 /*ThreadQuerySetWin32StartAddress*/, &ptr, sizeof( &ptr ), &retlen );
            if( status == 0 )
            {
                const auto phnd = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );
                if( phnd != INVALID_HANDLE_VALUE )
                {
                    MEMORY_BASIC_INFORMATION vmeminfo;
                    SIZE_T infosize = VirtualQueryEx( phnd, ptr, &vmeminfo, sizeof( vmeminfo ) );
                    if( infosize == sizeof( vmeminfo ) )
                    {
                        if (vmeminfo.Type == MEM_IMAGE)
                        {
                            // for MEM_IMAGE regions, vmeminfo.AllocationBase _is_ the HMODULE
                            HMODULE mod = (HMODULE)vmeminfo.AllocationBase;
                            MODULEINFO info;
                            if( _GetModuleInformation( phnd, mod, &info, sizeof( info ) ) != 0 )
                            {
                                char buf2[1024];
                                const auto modlen = _GetModuleBaseNameA( phnd, mod, buf2, 1024 );
                                if( modlen != 0 )
                                {
                                    threadName = CopyString( buf2, modlen );
                                    threadSent = true;
                                }
                            }
                        }
                    }
                    CloseHandle( phnd );
                }
            }
        }
        CloseHandle( hnd );
        if( !threadSent )
        {
            threadName = CopyString( "???", 3 );
            threadSent = true;
        }
        if( pid != 0 )
        {
            {
                uint64_t _pid = pid;
                TracyLfqPrepare( QueueType::TidToPid );
                MemWrite( &item->tidToPid.tid, thread );
                MemWrite( &item->tidToPid.pid, _pid );
                TracyLfqCommit;
            }
            if( pid == 4 )
            {
                name = CopyStringFast( "System", 6 );
                return;
            }
            else
            {
                const auto phnd = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
                if( phnd != INVALID_HANDLE_VALUE )
                {
                    char buf2[1024];
                    const auto sz = GetProcessImageFileNameA( phnd, buf2, 1024 );
                    CloseHandle( phnd );
                    if( sz != 0 )
                    {
                        auto ptr = buf2 + sz - 1;
                        while( ptr > buf2 && *ptr != '\\' ) ptr--;
                        if( *ptr == '\\' ) ptr++;
                        name = CopyStringFast( ptr );
                        return;
                    }
                }
            }
        }
    }

    if( !threadSent )
    {
        threadName = CopyString( "???", 3 );
    }
    name = CopyStringFast( "???", 3 );
}

}

#  elif defined __linux__

#    include <sys/types.h>
#    include <sys/stat.h>
#    include <sys/wait.h>
#    include <dirent.h>
#    include <fcntl.h>
#    include <inttypes.h>
#    include <limits>
#    include <mntent.h>
#    include <poll.h>
#    include <stdio.h>
#    include <stdlib.h>
#    include <string.h>
#    include <unistd.h>
#    include <atomic>
#    include <thread>
#    include <linux/perf_event.h>
#    include <linux/version.h>
#    include <sys/mman.h>
#    include <sys/ioctl.h>
#    include <sys/syscall.h>

#    if defined __i386 || defined __x86_64__
#      include "TracyCpuid.hpp"
#    endif

#    include "TracyProfiler.hpp"
#    include "TracyRingBuffer.hpp"
#    include "TracyThread.hpp"

namespace tracy
{

static std::atomic<bool> traceActive { false };
static int s_numCpus = 0;
static int s_numBuffers = 0;
static int s_ctxBufferIdx = 0;

static RingBuffer* s_ring = nullptr;

extern uint32_t ___tracy_magic_pid_override;

// (pid, cpu) pair for a per-task perf event open. In self-profiling mode we
// iterate one entry per CPU with pid = our tgid. In monitor mode we iterate
// one entry per existing thread of the target, with cpu = -1, so inherit=1
// can cover all descendants without multiplying ring buffers by CPU count.
struct PerfIterTarget
{
    pid_t pid;
    int cpu;
};

// Read /proc/<pid>/task/ and return the list of tids. Caller owns the buffer
// (tracy_free). Returns 0 and sets *out = nullptr on failure.
static int EnumerateTaskTids( pid_t pid, uint32_t** out )
{
    char path[64];
    snprintf( path, sizeof( path ), "/proc/%d/task", (int)pid );
    DIR* dir = opendir( path );
    if( !dir )
    {
        *out = nullptr;
        return 0;
    }
    size_t capacity = 32;
    uint32_t* tids = (uint32_t*)tracy_malloc( sizeof( uint32_t ) * capacity );
    size_t count = 0;
    struct dirent* entry;
    while( ( entry = readdir( dir ) ) != nullptr )
    {
        if( entry->d_name[0] == '.' ) continue;
        char* endp;
        unsigned long tid = strtoul( entry->d_name, &endp, 10 );
        if( *endp != '\0' || tid == 0 ) continue;
        if( count >= capacity )
        {
            capacity *= 2;
            tids = (uint32_t*)tracy_realloc( tids, sizeof( uint32_t ) * capacity );
        }
        tids[count++] = (uint32_t)tid;
    }
    closedir( dir );
    *out = tids;
    return (int)count;
}

static const int ThreadHashSize = 4 * 1024;
static uint32_t s_threadHash[ThreadHashSize] = {};

static bool CurrentProcOwnsThread( uint32_t tid )
{
    const auto hash = tid & ( ThreadHashSize-1 );
    const auto hv = s_threadHash[hash];
    if( hv == tid ) return true;
    if( hv == -tid ) return false;

    char path[256];
    if( ___tracy_magic_pid_override != 0 )
    {
        sprintf( path, "/proc/%d/task/%d", (int)___tracy_magic_pid_override, tid );
    }
    else
    {
        sprintf( path, "/proc/self/task/%d", tid );
    }
    struct stat st;
    if( stat( path, &st ) == 0 )
    {
        s_threadHash[hash] = tid;
        return true;
    }
    else
    {
        s_threadHash[hash] = -tid;
        return false;
    }
}

static int perf_event_open( struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags )
{
    return syscall( __NR_perf_event_open, hw_event, pid, cpu, group_fd, flags );
}

enum TraceEventId
{
    EventCallstack,
    EventCpuCycles,
    EventInstructionsRetired,
    EventCacheReference,
    EventCacheMiss,
    EventBranchRetired,
    EventBranchMiss,
    EventVsync,
    EventContextSwitch,
    EventWaking,
};

static void ProbePreciseIp( perf_event_attr& pe, unsigned long long config0, unsigned long long config1, pid_t pid )
{
    pe.config = config1;
    pe.precise_ip = 3;
    while( pe.precise_ip != 0 )
    {
        const int fd = perf_event_open( &pe, pid, 0, -1, PERF_FLAG_FD_CLOEXEC );
        if( fd != -1 )
        {
            close( fd );
            break;
        }
        pe.precise_ip--;
    }
    pe.config = config0;
    while( pe.precise_ip != 0 )
    {
        const int fd = perf_event_open( &pe, pid, 0, -1, PERF_FLAG_FD_CLOEXEC );
        if( fd != -1 )
        {
            close( fd );
            break;
        }
        pe.precise_ip--;
    }
    TracyDebug( "  Probed precise_ip: %i", pe.precise_ip );
}

static void ProbePreciseIp( perf_event_attr& pe, pid_t pid )
{
    pe.precise_ip = 3;
    while( pe.precise_ip != 0 )
    {
        const int fd = perf_event_open( &pe, pid, 0, -1, PERF_FLAG_FD_CLOEXEC );
        if( fd != -1 )
        {
            close( fd );
            break;
        }
        pe.precise_ip--;
    }
    TracyDebug( "  Probed precise_ip: %i", pe.precise_ip );
}

static bool IsGenuineIntel()
{
#if defined __i386 || defined __x86_64__
    uint32_t regs[4] = {};
    __get_cpuid( 0, regs, regs+1, regs+2, regs+3 );
    char manufacturer[12];
    memcpy( manufacturer, regs+1, 4 );
    memcpy( manufacturer+4, regs+3, 4 );
    memcpy( manufacturer+8, regs+2, 4 );
    return memcmp( manufacturer, "GenuineIntel", 12 ) == 0;
#else
    return false;
#endif
}

static const char* ReadFile( const char* path )
{
    int fd = open( path, O_RDONLY );
    if( fd < 0 ) return nullptr;

    static char tmp[64];
    const auto cnt = read( fd, tmp, 63 );
    close( fd );
    if( cnt < 0 ) return nullptr;
    tmp[cnt] = '\0';
    return tmp;
}

static const char* ReadFile( const char* base, const char* path )
{
    const auto blen = strlen( base );
    const auto plen = strlen( path );

    auto tmp = (char*)tracy_malloc( blen + plen + 1 );
    memcpy( tmp, base, blen );
    memcpy( tmp + blen, path, plen );
    tmp[blen+plen] = '\0';

    auto res = ReadFile( tmp );
    tracy_free( tmp );
    return res;
}

static char* GetTraceFsPath()
{
    auto f = setmntent( "/proc/mounts", "r" );
    if( !f ) return nullptr;

    char* ret = nullptr;
    while( auto ent = getmntent( f ) )
    {
        if( strcmp( ent->mnt_type, "tracefs" ) == 0 )
        {
            auto len = strlen( ent->mnt_dir );
            // ret may be != nullptr if we already saw a debugfs entry
            ret = (char*)tracy_realloc( ret, len + 1 );
            memcpy( ret, ent->mnt_dir, len );
            ret[len] = '\0';
            break;
        }
        else if( !ret && strcmp( ent->mnt_type, "debugfs" ) == 0 )
        {
            const char* tracingDirName = "tracing";
            const size_t tracingDirNameLen = strlen( tracingDirName );
            auto debugFsPathLen = strlen( ent->mnt_dir );
            ret = (char*)tracy_malloc( debugFsPathLen + 1 + tracingDirNameLen + 1 );
            memcpy( ret, ent->mnt_dir, debugFsPathLen );
            ret[debugFsPathLen] = '/';
            memcpy( ret + debugFsPathLen + 1, tracingDirName, tracingDirNameLen );
            ret[debugFsPathLen + 1 + tracingDirNameLen] = '\0';
            // Don't break to allow for tracefs to be found later as it is the preferred path
        }
    }
    endmntent( f );
    return ret;
}

bool SysTraceStart( int64_t& samplingPeriod )
{
#ifndef CLOCK_MONOTONIC_RAW
    return false;
#endif

    const auto paranoidLevelStr = ReadFile( "/proc/sys/kernel/perf_event_paranoid" );
    if( !paranoidLevelStr )
    {
        TracyDebug( "Failed to read perf_event_paranoid, cannot setup system tracing." );
        return false;
    }

    const int paranoidLevel = atoi( paranoidLevelStr );
    TracyDebug( "perf_event_paranoid: %i", paranoidLevel );

    auto traceFsPath = GetTraceFsPath();
    if( !traceFsPath )
    {
        TracyDebug( "Failed to get tracefs path, cannot setup system tracing." );
        return false;
    }
    TracyDebug( "tracefs path: %s", traceFsPath );

    int switchId = -1, wakingId = -1, vsyncId = -1;
    const auto switchIdStr = ReadFile( traceFsPath, "/events/sched/sched_switch/id" );
    if( switchIdStr ) switchId = atoi( switchIdStr );
    const auto wakingIdStr = ReadFile( traceFsPath, "/events/sched/sched_waking/id" );
    if( wakingIdStr ) wakingId = atoi( wakingIdStr );
    const auto vsyncIdStr = ReadFile( traceFsPath, "/events/drm/drm_vblank_event/id" );
    if( vsyncIdStr ) vsyncId = atoi( vsyncIdStr );

    tracy_free( traceFsPath );

    TracyDebug( "sched_switch id: %i", switchId );
    TracyDebug( "sched_waking id: %i", wakingId );
    TracyDebug( "drm_vblank_event id: %i", vsyncId );

    bool useMonotonicClockRaw = !HardwareSupportsInvariantTSC();
#if !defined TRACY_HW_TIMER || !defined TRACY_HAS_RDTSC
    useMonotonicClockRaw = true;
#endif
    if( useMonotonicClockRaw )
    {
        TracyDebug( "Using CLOCK_MONOTONIC_RAW for Linux perf events." );
    }

#ifdef TRACY_NO_SAMPLING
    const bool noSoftwareSampling = true;
#else
    const char* noSoftwareSamplingEnv = GetEnvVar( "TRACY_NO_SAMPLING" );
    const bool noSoftwareSampling = noSoftwareSamplingEnv && noSoftwareSamplingEnv[0] == '1';
#endif

#ifdef TRACY_NO_SAMPLE_RETIREMENT
    const bool noRetirement = true;
#else
    const char* noRetirementEnv = GetEnvVar( "TRACY_NO_SAMPLE_RETIREMENT" );
    const bool noRetirement = noRetirementEnv && noRetirementEnv[0] == '1';
#endif

#ifdef TRACY_NO_SAMPLE_CACHE
    const bool noCache = true;
#else
    const char* noCacheEnv = GetEnvVar( "TRACY_NO_SAMPLE_CACHE" );
    const bool noCache = noCacheEnv && noCacheEnv[0] == '1';
#endif

#ifdef TRACY_NO_SAMPLE_BRANCH
    const bool noBranch = true;
#else
    const char* noBranchEnv = GetEnvVar( "TRACY_NO_SAMPLE_BRANCH" );
    const bool noBranch = noBranchEnv && noBranchEnv[0] == '1';
#endif

#ifdef TRACY_NO_CONTEXT_SWITCH
    const bool noCtxSwitch = true;
#else
    const char* noCtxSwitchEnv = GetEnvVar( "TRACY_NO_CONTEXT_SWITCH" );
    const bool noCtxSwitch = noCtxSwitchEnv && noCtxSwitchEnv[0] == '1';
#endif

#ifdef TRACY_NO_VSYNC_CAPTURE
    const bool noVsync = true;
#else
    const char* noVsyncEnv = GetEnvVar( "TRACY_NO_VSYNC_CAPTURE" );
    const bool noVsync = noVsyncEnv && noVsyncEnv[0] == '1';
#endif

    int samplingFrequency = GetSamplingFrequency();
    if( samplingFrequency > 0 )
    {
        const auto maxSampleRateStr = ReadFile( "/proc/sys/kernel/perf_event_max_sample_rate" );
        if( maxSampleRateStr )
        {
            const int sysMax = atoi( maxSampleRateStr );
            if( sysMax > 0 && sysMax < samplingFrequency )
            {
                TracyDebug( "Requested sampling frequency %d Hz is higher than system maximum of %d Hz, reducing to system maximum.", samplingFrequency, sysMax );
                samplingFrequency = sysMax;
            }
        }
    }
    samplingPeriod = SamplingFrequencyToPeriodNs( samplingFrequency );
    uint32_t currentPid = ___tracy_magic_pid_override != 0 ? ___tracy_magic_pid_override : (uint32_t)getpid();

    s_numCpus = (int)std::thread::hardware_concurrency();

    // Build the per-task iteration list. In monitor mode this is all existing
    // threads of the target (one event per thread, any CPU); in self-profiling
    // it is per-CPU bound to our own tgid.
    PerfIterTarget* iter = nullptr;
    int numIter = 0;
    if( ___tracy_magic_pid_override != 0 )
    {
        uint32_t* tids = nullptr;
        const int numTids = EnumerateTaskTids( (pid_t)currentPid, &tids );
        if( numTids == 0 )
        {
            TracyDebug( "Failed to enumerate threads of pid %u; target may have exited.", currentPid );
            return false;
        }
        iter = (PerfIterTarget*)tracy_malloc( sizeof( PerfIterTarget ) * numTids );
        for( int i=0; i<numTids; i++ ) iter[i] = { (pid_t)tids[i], -1 };
        numIter = numTids;
        tracy_free( tids );
        TracyDebug( "Monitor mode: tracing %i existing threads of pid %u", numIter, currentPid );
    }
    else
    {
        iter = (PerfIterTarget*)tracy_malloc( sizeof( PerfIterTarget ) * s_numCpus );
        for( int i=0; i<s_numCpus; i++ ) iter[i] = { (pid_t)currentPid, i };
        numIter = s_numCpus;
    }

    const auto maxNumBuffers = numIter * (
        1 +     // software sampling
        2 +     // CPU cycles + instructions retired
        2 +     // cache reference + miss
        2       // branch retired + miss
    ) + s_numCpus * (
        2 +     // context switches + waking ups
        1       // vsync
    );
    s_ring = (RingBuffer*)tracy_malloc( sizeof( RingBuffer ) * maxNumBuffers );
    s_numBuffers = 0;

    // software sampling
    perf_event_attr pe = {};
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof( perf_event_attr );
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_freq = samplingFrequency;
    pe.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN;
#if LINUX_VERSION_CODE >= KERNEL_VERSION( 4, 8, 0 )
    pe.sample_max_stack = 127;
#endif
    pe.disabled = 1;
    pe.freq = 1;
    pe.inherit = 1;
    if( useMonotonicClockRaw )
    {
        pe.use_clockid = 1;
        pe.clockid = CLOCK_MONOTONIC_RAW;
    }

    if( !noSoftwareSampling )
    {
        TracyDebug( "Setup software sampling" );
        ProbePreciseIp( pe, currentPid );
        for( int i=0; i<numIter; i++ )
        {
            int fd = perf_event_open( &pe, iter[i].pid, iter[i].cpu, -1, PERF_FLAG_FD_CLOEXEC );
            if( fd == -1 )
            {
                pe.exclude_kernel = 1;
                ProbePreciseIp( pe, currentPid );
                fd = perf_event_open( &pe, iter[i].pid, iter[i].cpu, -1, PERF_FLAG_FD_CLOEXEC );
                if( fd == -1 )
                {
                    TracyDebug( "  Failed to setup!");
                    break;
                }
                TracyDebug( "  No access to kernel samples" );
            }
            new( s_ring+s_numBuffers ) RingBuffer( 64*1024, fd, EventCallstack );
            if( s_ring[s_numBuffers].IsValid() )
            {
                s_numBuffers++;
                TracyDebug( "  Target %i ok", i );
            }
        }
    }

    // CPU cycles + instructions retired
    pe = {};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof( perf_event_attr );
    pe.sample_freq = 5000;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TIME;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_guest = 1;
    pe.exclude_hv = 1;
    pe.freq = 1;
    pe.inherit = 1;
    if( useMonotonicClockRaw )
    {
        pe.use_clockid = 1;
        pe.clockid = CLOCK_MONOTONIC_RAW;
    }

    if( !noRetirement )
    {
        TracyDebug( "Setup sampling cycles + retirement" );
        ProbePreciseIp( pe, PERF_COUNT_HW_CPU_CYCLES, PERF_COUNT_HW_INSTRUCTIONS, currentPid );
        for( int i=0; i<numIter; i++ )
        {
            const int fd = perf_event_open( &pe, iter[i].pid, iter[i].cpu, -1, PERF_FLAG_FD_CLOEXEC );
            if( fd != -1 )
            {
                new( s_ring+s_numBuffers ) RingBuffer( 64*1024, fd, EventCpuCycles );
                if( s_ring[s_numBuffers].IsValid() )
                {
                    s_numBuffers++;
                    TracyDebug( "  Target %i ok", i );
                }
            }
        }

        pe.config = PERF_COUNT_HW_INSTRUCTIONS;
        for( int i=0; i<numIter; i++ )
        {
            const int fd = perf_event_open( &pe, iter[i].pid, iter[i].cpu, -1, PERF_FLAG_FD_CLOEXEC );
            if( fd != -1 )
            {
                new( s_ring+s_numBuffers ) RingBuffer( 64*1024, fd, EventInstructionsRetired );
                if( s_ring[s_numBuffers].IsValid() )
                {
                    s_numBuffers++;
                    TracyDebug( "  Target %i ok", i );
                }
            }
        }
    }

    // cache reference + miss
    if( !noCache )
    {
        TracyDebug( "Setup sampling CPU cache references + misses" );
        ProbePreciseIp( pe, PERF_COUNT_HW_CACHE_REFERENCES, PERF_COUNT_HW_CACHE_MISSES, currentPid );
        if( IsGenuineIntel() )
        {
            pe.precise_ip = 0;
            TracyDebug( "  CPU is GenuineIntel, forcing precise_ip down to 0" );
        }
        for( int i=0; i<numIter; i++ )
        {
            const int fd = perf_event_open( &pe, iter[i].pid, iter[i].cpu, -1, PERF_FLAG_FD_CLOEXEC );
            if( fd != -1 )
            {
                new( s_ring+s_numBuffers ) RingBuffer( 64*1024, fd, EventCacheReference );
                if( s_ring[s_numBuffers].IsValid() )
                {
                    s_numBuffers++;
                    TracyDebug( "  Target %i ok", i );
                }
            }
        }

        pe.config = PERF_COUNT_HW_CACHE_MISSES;
        for( int i=0; i<numIter; i++ )
        {
            const int fd = perf_event_open( &pe, iter[i].pid, iter[i].cpu, -1, PERF_FLAG_FD_CLOEXEC );
            if( fd != -1 )
            {
                new( s_ring+s_numBuffers ) RingBuffer( 64*1024, fd, EventCacheMiss );
                if( s_ring[s_numBuffers].IsValid() )
                {
                    s_numBuffers++;
                    TracyDebug( "  Target %i ok", i );
                }
            }
        }
    }

    // branch retired + miss
    if( !noBranch )
    {
        TracyDebug( "Setup sampling CPU branch retirements + misses" );
        ProbePreciseIp( pe, PERF_COUNT_HW_BRANCH_INSTRUCTIONS, PERF_COUNT_HW_BRANCH_MISSES, currentPid );
        for( int i=0; i<numIter; i++ )
        {
            const int fd = perf_event_open( &pe, iter[i].pid, iter[i].cpu, -1, PERF_FLAG_FD_CLOEXEC );
            if( fd != -1 )
            {
                new( s_ring+s_numBuffers ) RingBuffer( 64*1024, fd, EventBranchRetired );
                if( s_ring[s_numBuffers].IsValid() )
                {
                    s_numBuffers++;
                    TracyDebug( "  Target %i ok", i );
                }
            }
        }

        pe.config = PERF_COUNT_HW_BRANCH_MISSES;
        for( int i=0; i<numIter; i++ )
        {
            const int fd = perf_event_open( &pe, iter[i].pid, iter[i].cpu, -1, PERF_FLAG_FD_CLOEXEC );
            if( fd != -1 )
            {
                new( s_ring+s_numBuffers ) RingBuffer( 64*1024, fd, EventBranchMiss );
                if( s_ring[s_numBuffers].IsValid() )
                {
                    s_numBuffers++;
                    TracyDebug( "  Target %i ok", i );
                }
            }
        }
    }

    s_ctxBufferIdx = s_numBuffers;

    // vsync
    if( !noVsync && vsyncId != -1 )
    {
        pe = {};
        pe.type = PERF_TYPE_TRACEPOINT;
        pe.size = sizeof( perf_event_attr );
        pe.sample_period = 1;
        pe.sample_type = PERF_SAMPLE_TIME | PERF_SAMPLE_RAW;
        pe.disabled = 1;
        pe.config = vsyncId;
        if( useMonotonicClockRaw )
        {
            pe.use_clockid = 1;
            pe.clockid = CLOCK_MONOTONIC_RAW;
        }

        TracyDebug( "Setup vsync capture" );
        for( int i=0; i<s_numCpus; i++ )
        {
            const int fd = perf_event_open( &pe, -1, i, -1, PERF_FLAG_FD_CLOEXEC );
            if( fd != -1 )
            {
                new( s_ring+s_numBuffers ) RingBuffer( 64*1024, fd, EventVsync, i );
                if( s_ring[s_numBuffers].IsValid() )
                {
                    s_numBuffers++;
                    TracyDebug( "  Core %i ok", i );
                }
            }
        }
    }

    // context switches
    if( !noCtxSwitch && switchId != -1 )
    {
        pe = {};
        pe.type = PERF_TYPE_TRACEPOINT;
        pe.size = sizeof( perf_event_attr );
        pe.sample_period = 1;
        pe.sample_type = PERF_SAMPLE_TIME | PERF_SAMPLE_RAW | PERF_SAMPLE_CALLCHAIN;
#if LINUX_VERSION_CODE >= KERNEL_VERSION( 4, 8, 0 )
        pe.sample_max_stack = 127;
#endif
        pe.disabled = 1;
        pe.inherit = 1;
        pe.config = switchId;
        if( useMonotonicClockRaw )
        {
            pe.use_clockid = 1;
            pe.clockid = CLOCK_MONOTONIC_RAW;
        }

        TracyDebug( "Setup context switch capture" );
        for( int i=0; i<s_numCpus; i++ )
        {
            const int fd = perf_event_open( &pe, -1, i, -1, PERF_FLAG_FD_CLOEXEC );
            if( fd != -1 )
            {
                new( s_ring+s_numBuffers ) RingBuffer( 256*1024, fd, EventContextSwitch, i );
                if( s_ring[s_numBuffers].IsValid() )
                {
                    s_numBuffers++;
                    TracyDebug( "  Core %i ok", i );
                }
            }
        }

        if( wakingId != -1 )
        {
            pe = {};
            pe.type = PERF_TYPE_TRACEPOINT;
            pe.size = sizeof( perf_event_attr );
            pe.sample_period = 1;
            pe.sample_type = PERF_SAMPLE_TIME | PERF_SAMPLE_RAW;
            // Coult ask for callstack here
            //pe.sample_type |= PERF_SAMPLE_CALLCHAIN;
            pe.disabled = 1;
            pe.inherit = 1;
            pe.config = wakingId;
            pe.read_format = 0;
            if( useMonotonicClockRaw )
            {
                pe.use_clockid = 1;
                pe.clockid = CLOCK_MONOTONIC_RAW;
            }

            TracyDebug( "Setup waking up capture" );
            for( int i=0; i<s_numCpus; i++ )
            {
                const int fd = perf_event_open( &pe, -1, i, -1, PERF_FLAG_FD_CLOEXEC );
                if( fd != -1 )
                {
                    new( s_ring+s_numBuffers ) RingBuffer( 64*1024, fd, EventWaking, i );
                    if( s_ring[s_numBuffers].IsValid() )
                    {
                        s_numBuffers++;
                        TracyDebug( "  Core %i ok", i );
                    }
                }
            }
        }
    }

    TracyDebug( "Ringbuffers in use: %i", s_numBuffers );

    tracy_free( iter );

    traceActive.store( true, std::memory_order_relaxed );
    return true;
}

void SysTraceStop()
{
    traceActive.store( false, std::memory_order_relaxed );
}

static uint64_t* GetCallstackBlock( uint64_t cnt, RingBuffer& ring, uint64_t offset )
{
    auto trace = (uint64_t*)tracy_malloc_fast( ( 1 + cnt ) * sizeof( uint64_t ) );
    ring.Read( trace+1, offset, sizeof( uint64_t ) * cnt );

#if defined __x86_64__ || defined _M_X64
    // remove non-canonical pointers
    do
    {
        const auto test = (int64_t)trace[cnt];
        const auto m1 = test >> 63;
        const auto m2 = test >> 47;
        if( m1 == m2 ) break;
    }
    while( --cnt > 0 );
    for( uint64_t j=1; j<cnt; j++ )
    {
        const auto test = (int64_t)trace[j];
        const auto m1 = test >> 63;
        const auto m2 = test >> 47;
        if( m1 != m2 ) trace[j] = 0;
    }
#endif

    for( uint64_t j=1; j<=cnt; j++ )
    {
        if( trace[j] >= (uint64_t)-4095 )       // PERF_CONTEXT_MAX
        {
            memmove( trace+j, trace+j+1, sizeof( uint64_t ) * ( cnt - j ) );
            cnt--;
        }
    }

    memcpy( trace, &cnt, sizeof( uint64_t ) );
    return trace;
}

void SysTraceWorker( void* ptr )
{
    ThreadExitHandler threadExitHandler;
    SetThreadName( "Tracy Sampling" );
    InitAllocator();
    sched_param sp = { 99 };
    if( pthread_setschedparam( pthread_self(), SCHED_FIFO, &sp ) != 0 ) TracyDebug( "Failed to increase SysTraceWorker thread priority!" );
    auto ctxBufferIdx = s_ctxBufferIdx;
    auto ringArray = s_ring;
    auto numBuffers = s_numBuffers;
    for( int i=0; i<numBuffers; i++ ) ringArray[i].Enable();
    for(;;)
    {
#ifdef TRACY_ON_DEMAND
        if( !GetProfiler().IsConnected() )
        {
            if( !traceActive.load( std::memory_order_relaxed ) ) break;
            for( int i=0; i<numBuffers; i++ )
            {
                auto& ring = ringArray[i];
                const auto head = ring.LoadHead();
                const auto tail = ring.GetTail();
                if( head != tail )
                {
                    const auto end = head - tail;
                    ring.Advance( end );
                }
            }
            if( !traceActive.load( std::memory_order_relaxed ) ) break;
            std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            continue;
        }
#endif

        bool hadData = false;
        for( int i=0; i<ctxBufferIdx; i++ )
        {
            if( !traceActive.load( std::memory_order_relaxed ) ) break;
            auto& ring = ringArray[i];
            const auto head = ring.LoadHead();
            const auto tail = ring.GetTail();
            if( head == tail ) continue;
            assert( head > tail );
            hadData = true;

            const auto id = ring.GetId();
            assert( id != EventContextSwitch );
            const auto end = head - tail;
            uint64_t pos = 0;
            if( id == EventCallstack )
            {
                while( pos < end )
                {
                    perf_event_header hdr;
                    ring.Read( &hdr, pos, sizeof( perf_event_header ) );
                    if( hdr.type == PERF_RECORD_SAMPLE )
                    {
                        auto offset = pos + sizeof( perf_event_header );

                        // Layout:
                        //   u32 pid, tid
                        //   u64 time
                        //   u64 cnt
                        //   u64 ip[cnt]

#pragma pack( push, 1 )
                        struct
                        {
                            uint32_t tid;
                            uint64_t t0;
                            uint64_t cnt;
                        } buf;
#pragma pack( pop )

                        offset += sizeof( uint32_t );
                        ring.Read( &buf, offset, sizeof( buf ) );
                        offset += sizeof( buf );

                        if( buf.cnt > 0 )
                        {
#if defined TRACY_HW_TIMER && defined TRACY_HAS_RDTSC
                            buf.t0 = ring.ConvertTimeToTsc( buf.t0 );
#endif
                            auto trace = GetCallstackBlock( buf.cnt, ring, offset );

                            TracyLfqPrepare( QueueType::CallstackSample );
                            MemWrite( &item->callstackSampleFat.time, buf.t0 );
                            MemWrite( &item->callstackSampleFat.thread, buf.tid );
                            MemWrite( &item->callstackSampleFat.ptr, (uint64_t)trace );
                            TracyLfqCommit;
                        }
                    }
                    pos += hdr.size;
                }
            }
            else
            {
                while( pos < end )
                {
                    perf_event_header hdr;
                    ring.Read( &hdr, pos, sizeof( perf_event_header ) );
                    if( hdr.type == PERF_RECORD_SAMPLE )
                    {
                        auto offset = pos + sizeof( perf_event_header );

                        // Layout:
                        //   u64 ip
                        //   u64 time

                        struct
                        {
                            uint64_t ip, t0;
                        } buf;

                        ring.Read( &buf, offset, sizeof( buf ) );

#if defined TRACY_HW_TIMER && defined TRACY_HAS_RDTSC
                        buf.t0 = ring.ConvertTimeToTsc( buf.t0 );
#endif
                        QueueType type;
                        switch( id )
                        {
                        case EventCpuCycles:
                            type = QueueType::HwSampleCpuCycle;
                            break;
                        case EventInstructionsRetired:
                            type = QueueType::HwSampleInstructionRetired;
                            break;
                        case EventCacheReference:
                            type = QueueType::HwSampleCacheReference;
                            break;
                        case EventCacheMiss:
                            type = QueueType::HwSampleCacheMiss;
                            break;
                        case EventBranchRetired:
                            type = QueueType::HwSampleBranchRetired;
                            break;
                        case EventBranchMiss:
                            type = QueueType::HwSampleBranchMiss;
                            break;
                        default:
                            abort();
                        }

                        TracyLfqPrepare( type );
                        MemWrite( &item->hwSample.ip, buf.ip );
                        MemWrite( &item->hwSample.time, buf.t0 );
                        TracyLfqCommit;
                    }
                    pos += hdr.size;
                }
            }
            assert( pos == end );
            ring.Advance( end );
        }
        if( !traceActive.load( std::memory_order_relaxed ) ) break;

        if( ctxBufferIdx != numBuffers )
        {
            const auto ctxBufNum = numBuffers - ctxBufferIdx;

            int activeNum = 0;
            uint16_t active[512];
            uint32_t end[512];
            uint32_t pos[512];
            int64_t time[512];

            auto PrimeNext = [&pos, &end, &time]( int idx, RingBuffer& ring ) {
                while( pos[idx] < end[idx] )
                {
                    perf_event_header hdr;
                    ring.Read( &hdr, pos[idx], sizeof( hdr ) );
                    if( hdr.type == PERF_RECORD_SAMPLE )
                    {
                        ring.Read( time + idx, pos[idx] + sizeof( hdr ), sizeof( int64_t ) );
                        return true;
                    }
                    assert( hdr.size > 0 );
                    pos[idx] += hdr.size;
                }
                return false;
            };

            for( int i=0; i<ctxBufNum; i++ )
            {
                const auto rbIdx = ctxBufferIdx + i;
                const auto rbHead = ringArray[rbIdx].LoadHead();
                const auto rbTail = ringArray[rbIdx].GetTail();

                if( rbHead != rbTail )
                {
                    end[i] = rbHead - rbTail;
                    pos[i] = 0;
                    if( PrimeNext( i, ringArray[rbIdx] ) )
                    {
                        active[activeNum] = (uint16_t)i;
                        activeNum++;
                    }
                }
                else
                {
                    end[i] = 0;
                }
            }
            if( activeNum > 0 )
            {
                hadData = true;
                while( activeNum > 0 )
                {
                    // Find the earliest event from the active buffers
                    int sel = -1;
                    int selPos;
                    int64_t t0 = std::numeric_limits<int64_t>::max();
                    for( int i=0; i<activeNum; i++ )
                    {
                        auto idx = active[i];
                        if( time[idx] < t0 )
                        {
                            t0 = time[idx];
                            sel = idx;
                            selPos = i;
                        }
                    }
                    // Found any event
                    if( sel >= 0 )
                    {
                        assert( pos[sel] < end[sel] );

                        auto& ring = ringArray[ctxBufferIdx + sel];
                        auto rbPos = pos[sel];
                        auto offset = rbPos;
                        perf_event_header hdr;
                        ring.Read( &hdr, offset, sizeof( perf_event_header ) );

#if defined TRACY_HW_TIMER && defined TRACY_HAS_RDTSC
                        t0 = ring.ConvertTimeToTsc( t0 );
#endif

                        const auto rid = ring.GetId();
                        if( rid == EventContextSwitch )
                        {
                            // Layout: See /sys/kernel/debug/tracing/events/sched/sched_switch/format
                            //   u64 time    // PERF_SAMPLE_TIME
                            //   u64 cnt     // PERF_SAMPLE_CALLCHAIN
                            //   u64 ip[cnt] // PERF_SAMPLE_CALLCHAIN
                            //   u32 size
                            //   u8  data[size]
                            // Data (not ABI stable, but has not changed since it was added, in 2009):
                            //   u8  hdr[8]
                            //   u8  prev_comm[16]
                            //   u32 prev_pid
                            //   u32 prev_prio
                            //   lng prev_state
                            //   u8  next_comm[16]
                            //   u32 next_pid
                            //   u32 next_prio

                            offset += sizeof( perf_event_header ) + sizeof( uint64_t );

                            uint64_t cnt;
                            ring.Read( &cnt, offset, sizeof( uint64_t ) );
                            offset += sizeof( uint64_t );
                            const auto traceOffset = offset;
                            offset += sizeof( uint64_t ) * cnt + sizeof( uint32_t ) + 8 + 16;

                            struct
                            {
                                uint32_t prev_pid, prev_prio;
                                long prev_state;
                                char next_comm[16];
                                uint32_t next_pid, next_prio;
                            } buf;

                            ring.Read( &buf, offset, sizeof( buf ) );

                            uint8_t oldThreadWaitReason = 100;
                            uint8_t oldThreadState;

                            if(      buf.prev_state & 0x0001 ) oldThreadState = 104;
                            else if( buf.prev_state & 0x0002 ) oldThreadState = 101;
                            else if( buf.prev_state & 0x0004 ) oldThreadState = 105;
                            else if( buf.prev_state & 0x0008 ) oldThreadState = 106;
                            else if( buf.prev_state & 0x0010 ) oldThreadState = 108;
                            else if( buf.prev_state & 0x0020 ) oldThreadState = 109;
                            else if( buf.prev_state & 0x0040 ) oldThreadState = 110;
                            else if( buf.prev_state & 0x0080 ) oldThreadState = 102;
                            else                           oldThreadState = 103;

                            TracyLfqPrepare( QueueType::ContextSwitch );
                            MemWrite( &item->contextSwitch.time, t0 );
                            MemWrite( &item->contextSwitch.oldThread, buf.prev_pid );
                            MemWrite( &item->contextSwitch.newThread, buf.next_pid );
                            MemWrite( &item->contextSwitch.cpu, uint8_t( ring.GetCpu() ) );
                            MemWrite( &item->contextSwitch.oldThreadWaitReason, oldThreadWaitReason );
                            MemWrite( &item->contextSwitch.oldThreadState, oldThreadState );
                            MemWrite( &item->contextSwitch.previousCState, uint8_t( 0 ) );
                            MemWrite( &item->contextSwitch.newThreadPriority, int8_t( buf.next_prio ) );
                            MemWrite( &item->contextSwitch.oldThreadPriority, int8_t( buf.prev_prio ) );
                            TracyLfqCommit;

                            if( cnt > 0 && buf.prev_pid != 0 && CurrentProcOwnsThread( buf.prev_pid ) )
                            {
                                auto trace = GetCallstackBlock( cnt, ring, traceOffset );

                                TracyLfqPrepare( QueueType::CallstackSampleContextSwitch );
                                MemWrite( &item->callstackSampleFat.time, t0 );
                                MemWrite( &item->callstackSampleFat.thread, buf.prev_pid );
                                MemWrite( &item->callstackSampleFat.ptr, (uint64_t)trace );
                                TracyLfqCommit;
                            }
                        }
                        else if( rid == EventWaking)
                        {
                            // See /sys/kernel/debug/tracing/events/sched/sched_waking/format
                            // Layout:
                            //   u64 time // PERF_SAMPLE_TIME
                            //   u32 size
                            //   u8  data[size]
                            // Data:
                            //   u8  hdr[8]
                            //   u8  comm[16]
                            //   u32 pid
                            //   i32 prio
                            //   i32 target_cpu
                            const uint32_t dataOffset = sizeof( perf_event_header ) + sizeof( uint64_t ) + sizeof( uint32_t ); 
                            offset += dataOffset + 8 + 16;
                            uint32_t pid;
                            ring.Read( &pid, offset, sizeof( uint32_t ) );
                            
                            TracyLfqPrepare( QueueType::ThreadWakeup );
                            MemWrite( &item->threadWakeup.time, t0 );
                            MemWrite( &item->threadWakeup.thread, pid );
                            MemWrite( &item->threadWakeup.cpu, (uint8_t)ring.GetCpu() );

                            int8_t adjustReason = -1; // Does not exist on Linux
                            int8_t adjustIncrement = 0; // Should perhaps store the new prio?
                            MemWrite( &item->threadWakeup.adjustReason, adjustReason );
                            MemWrite( &item->threadWakeup.adjustIncrement, adjustIncrement );
                            TracyLfqCommit;
                        }
                        else
                        {
                            assert( rid == EventVsync );
                            // Layout:
                            //   u64 time
                            //   u32 size
                            //   u8  data[size]
                            // Data (not ABI stable):
                            //   u8  hdr[8]
                            //   i32 crtc
                            //   u32 seq
                            //   i64 ktime
                            //   u8  high precision

                            offset += sizeof( perf_event_header ) + sizeof( uint64_t ) + sizeof( uint32_t ) + 8;

                            int32_t crtc;
                            ring.Read( &crtc, offset, sizeof( int32_t ) );

                            // Note: The timestamp value t0 might be off by a number of microseconds from the
                            // true hardware vblank event. The ktime value should be used instead, but it is
                            // measured in CLOCK_MONOTONIC time. Tracy only supports the timestamp counter
                            // register (TSC) or CLOCK_MONOTONIC_RAW clock.
#if 0
                            offset += sizeof( uint32_t ) * 2;
                            int64_t ktime;
                            ring.Read( &ktime, offset, sizeof( int64_t ) );
#endif

                            TracyLfqPrepare( QueueType::FrameVsync );
                            MemWrite( &item->frameVsync.id, crtc );
                            MemWrite( &item->frameVsync.time, t0 );
                            TracyLfqCommit;
                        }

                        rbPos += hdr.size;
                        pos[sel] = rbPos;
                        if( !PrimeNext( sel, ring ) )
                        {
                            active[selPos] = active[activeNum - 1];
                            activeNum--;
                        }
                    }
                }
                for( int i=0; i<ctxBufNum; i++ )
                {
                    if( end[i] != 0 ) ringArray[ctxBufferIdx + i].Advance( end[i] );
                }
            }
        }
        if( !traceActive.load( std::memory_order_relaxed ) ) break;
        if( !hadData )
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        }
    }

    for( int i=0; i<numBuffers; i++ ) ringArray[i].~RingBuffer();
    tracy_free_fast( ringArray );
}

void SysTraceGetExternalName( uint64_t thread, const char*& threadName, const char*& name )
{
    FILE* f;
    char fn[256];
    sprintf( fn, "/proc/%" PRIu64 "/comm", thread );
    f = fopen( fn, "rb" );
    if( f )
    {
        char buf[256];
        const auto sz = fread( buf, 1, 256, f );
        if( sz > 0 && buf[sz-1] == '\n' ) buf[sz-1] = '\0';
        threadName = CopyString( buf );
        fclose( f );
    }
    else
    {
        threadName = CopyString( "???", 3 );
    }

    sprintf( fn, "/proc/%" PRIu64 "/status", thread );
    f = fopen( fn, "rb" );
    if( f )
    {
        char* tmp = (char*)tracy_malloc_fast( 8*1024 );
        const auto fsz = (ptrdiff_t)fread( tmp, 1, 8*1024, f );
        fclose( f );

        int pid = -1;
        auto line = tmp;
        for(;;)
        {
            if( memcmp( "Tgid:\t", line, 6 ) == 0 )
            {
                pid = atoi( line + 6 );
                break;
            }
            while( line - tmp < fsz && *line != '\n' ) line++;
            if( *line != '\n' ) break;
            line++;
        }
        tracy_free_fast( tmp );

        if( pid >= 0 )
        {
            {
                uint64_t _pid = pid;
                TracyLfqPrepare( QueueType::TidToPid );
                MemWrite( &item->tidToPid.tid, thread );
                MemWrite( &item->tidToPid.pid, _pid );
                TracyLfqCommit;
            }
            sprintf( fn, "/proc/%i/comm", pid );
            f = fopen( fn, "rb" );
            if( f )
            {
                char buf[256];
                const auto sz = fread( buf, 1, 256, f );
                if( sz > 0 && buf[sz-1] == '\n' ) buf[sz-1] = '\0';
                name = CopyStringFast( buf );
                fclose( f );
                return;
            }
        }
    }
    name = CopyStringFast( "???", 3 );
}

}

#  elif defined __APPLE__

#    include "apple/TracyMach.cpp"

#  endif

#endif
