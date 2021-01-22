#include "TracySysTrace.hpp"

#ifdef TRACY_HAS_SYSTEM_TRACING

#  if defined _WIN32 || defined __CYGWIN__

#    ifndef NOMINMAX
#      define NOMINMAX
#    endif

#    define INITGUID
#    include <assert.h>
#    include <string.h>
#    include <windows.h>
#    include <dbghelp.h>
#    include <evntrace.h>
#    include <evntcons.h>
#    include <psapi.h>
#    include <winternl.h>

#    include "../common/TracyAlloc.hpp"
#    include "../common/TracySystem.hpp"
#    include "TracyProfiler.hpp"
#    include "TracyThread.hpp"

namespace tracy
{

static const GUID PerfInfoGuid = { 0xce1dbfb4, 0x137e, 0x4da6, { 0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc } };
static const GUID DxgKrnlGuid  = { 0x802ec45a, 0x1e99, 0x4b83, { 0x99, 0x20, 0x87, 0xc9, 0x82, 0x77, 0xba, 0x9d } };


static TRACEHANDLE s_traceHandle;
static TRACEHANDLE s_traceHandle2;
static EVENT_TRACE_PROPERTIES* s_prop;
static DWORD s_pid;

static EVENT_TRACE_PROPERTIES* s_propVsync;
static TRACEHANDLE s_traceHandleVsync;
static TRACEHANDLE s_traceHandleVsync2;
Thread* s_threadVsync = nullptr;

struct CSwitch
{
    uint32_t    newThreadId;
    uint32_t    oldThreadId;
    int8_t      newThreadPriority;
    int8_t      oldThreadPriority;
    uint8_t     previousCState;
    int8_t      spareByte;
    int8_t      oldThreadWaitReason;
    int8_t      oldThreadWaitMode;
    int8_t      oldThreadState;
    int8_t      oldThreadWaitIdealProcessor;
    uint32_t    newThreadWaitTime;
    uint32_t    reserved;
};

struct ReadyThread
{
    uint32_t    threadId;
    int8_t      adjustReason;
    int8_t      adjustIncrement;
    int8_t      flag;
    int8_t      reserverd;
};

struct ThreadTrace
{
    uint32_t processId;
    uint32_t threadId;
    uint32_t stackBase;
    uint32_t stackLimit;
    uint32_t userStackBase;
    uint32_t userStackLimit;
    uint32_t startAddr;
    uint32_t win32StartAddr;
    uint32_t tebBase;
    uint32_t subProcessTag;
};

struct StackWalkEvent
{
    uint64_t eventTimeStamp;
    uint32_t stackProcess;
    uint32_t stackThread;
    uint64_t stack[192];
};

struct VSyncInfo
{
    void*       dxgAdapter;
    uint32_t    vidPnTargetId;
    uint64_t    scannedPhysicalAddress;
    uint32_t    vidPnSourceId;
    uint32_t    frameNumber;
    int64_t     frameQpcTime;
    void*       hFlipDevice;
    uint32_t    flipType;
    uint64_t    flipFenceId;
};

#ifdef __CYGWIN__
extern "C" typedef DWORD (WINAPI *t_GetProcessIdOfThread)( HANDLE );
extern "C" typedef DWORD (WINAPI *t_GetProcessImageFileNameA)( HANDLE, LPSTR, DWORD );
extern "C" ULONG WMIAPI TraceSetInformation(TRACEHANDLE SessionHandle, TRACE_INFO_CLASS InformationClass, PVOID TraceInformation, ULONG InformationLength);
t_GetProcessIdOfThread GetProcessIdOfThread = (t_GetProcessIdOfThread)GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "GetProcessIdOfThread" );
t_GetProcessImageFileNameA GetProcessImageFileNameA = (t_GetProcessImageFileNameA)GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "K32GetProcessImageFileNameA" );
#endif

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
    switch( hdr.ProviderId.Data1 )
    {
    case 0x3d6fa8d1:    // Thread Guid
        if( hdr.EventDescriptor.Opcode == 36 )
        {
            const auto cswitch = (const CSwitch*)record->UserData;

            TracyLfqPrepare( QueueType::ContextSwitch );
            MemWrite( &item->contextSwitch.time, hdr.TimeStamp.QuadPart );
            memcpy( &item->contextSwitch.oldThread, &cswitch->oldThreadId, sizeof( cswitch->oldThreadId ) );
            memcpy( &item->contextSwitch.newThread, &cswitch->newThreadId, sizeof( cswitch->newThreadId ) );
            memset( ((char*)&item->contextSwitch.oldThread)+4, 0, 4 );
            memset( ((char*)&item->contextSwitch.newThread)+4, 0, 4 );
            MemWrite( &item->contextSwitch.cpu, record->BufferContext.ProcessorNumber );
            MemWrite( &item->contextSwitch.reason, cswitch->oldThreadWaitReason );
            MemWrite( &item->contextSwitch.state, cswitch->oldThreadState );
            TracyLfqCommit;
        }
        else if( hdr.EventDescriptor.Opcode == 50 )
        {
            const auto rt = (const ReadyThread*)record->UserData;

            TracyLfqPrepare( QueueType::ThreadWakeup );
            MemWrite( &item->threadWakeup.time, hdr.TimeStamp.QuadPart );
            memcpy( &item->threadWakeup.thread, &rt->threadId, sizeof( rt->threadId ) );
            memset( ((char*)&item->threadWakeup.thread)+4, 0, 4 );
            TracyLfqCommit;
        }
        else if( hdr.EventDescriptor.Opcode == 1 || hdr.EventDescriptor.Opcode == 3 )
        {
            const auto tt = (const ThreadTrace*)record->UserData;

            uint64_t tid = tt->threadId;
            if( tid == 0 ) return;
            uint64_t pid = tt->processId;
            TracyLfqPrepare( QueueType::TidToPid );
            MemWrite( &item->tidToPid.tid, tid );
            MemWrite( &item->tidToPid.pid, pid );
            TracyLfqCommit;
        }
        break;
    case 0xdef2fe46:    // StackWalk Guid
        if( hdr.EventDescriptor.Opcode == 32 )
        {
            const auto sw = (const StackWalkEvent*)record->UserData;
            if( sw->stackProcess == s_pid && ( sw->stack[0] & 0x8000000000000000 ) == 0 )
            {
                const uint64_t sz = ( record->UserDataLength - 16 ) / 8;
                if( sz > 0 )
                {
                    auto trace = (uint64_t*)tracy_malloc( ( 1 + sz ) * sizeof( uint64_t ) );
                    memcpy( trace, &sz, sizeof( uint64_t ) );
                    memcpy( trace+1, sw->stack, sizeof( uint64_t ) * sz );
                    TracyLfqPrepare( QueueType::CallstackSample );
                    MemWrite( &item->callstackSampleFat.time, sw->eventTimeStamp );
                    MemWrite( &item->callstackSampleFat.thread, (uint64_t)sw->stackThread );
                    MemWrite( &item->callstackSampleFat.ptr, (uint64_t)trace );
                    TracyLfqCommit;
                }
            }
        }
        break;
    default:
        break;
    }
}

static constexpr const char* VsyncName[] = {
    "[0] Vsync",
    "[1] Vsync",
    "[2] Vsync",
    "[3] Vsync",
    "[4] Vsync",
    "[5] Vsync",
    "[6] Vsync",
    "[7] Vsync",
    "Vsync"
};

static uint32_t VsyncTarget[8] = {};

void WINAPI EventRecordCallbackVsync( PEVENT_RECORD record )
{
#ifdef TRACY_ON_DEMAND
    if( !GetProfiler().IsConnected() ) return;
#endif

    const auto& hdr = record->EventHeader;
    assert( hdr.ProviderId.Data1 == 0x802EC45A );
    assert( hdr.EventDescriptor.Id == 0x0011 );

    const auto vs = (const VSyncInfo*)record->UserData;

    int idx = 0;
    do
    {
        if( VsyncTarget[idx] == 0 )
        {
            VsyncTarget[idx] = vs->vidPnTargetId;
            break;
        }
        else if( VsyncTarget[idx] == vs->vidPnTargetId )
        {
            break;
        }
    }
    while( ++idx < 8 );

    TracyLfqPrepare( QueueType::FrameMarkMsg );
    MemWrite( &item->frameMark.time, hdr.TimeStamp.QuadPart );
    MemWrite( &item->frameMark.name, uint64_t( VsyncName[idx] ) );
    TracyLfqCommit;
}

static void SetupVsync()
{
#if _WIN32_WINNT >= _WIN32_WINNT_WINBLUE
    const auto psz = sizeof( EVENT_TRACE_PROPERTIES ) + MAX_PATH;
    s_propVsync = (EVENT_TRACE_PROPERTIES*)tracy_malloc( psz );
    memset( s_propVsync, 0, sizeof( EVENT_TRACE_PROPERTIES ) );
    s_propVsync->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    s_propVsync->Wnode.BufferSize = psz;
#ifdef TRACY_TIMER_QPC
    s_propVsync->Wnode.ClientContext = 1;
#else
    s_propVsync->Wnode.ClientContext = 3;
#endif
    s_propVsync->LoggerNameOffset = sizeof( EVENT_TRACE_PROPERTIES );
    strcpy( ((char*)s_propVsync) + sizeof( EVENT_TRACE_PROPERTIES ), "TracyVsync" );

    auto backup = tracy_malloc( psz );
    memcpy( backup, s_propVsync, psz );

    const auto controlStatus = ControlTraceA( 0, "TracyVsync", s_propVsync, EVENT_TRACE_CONTROL_STOP );
    if( controlStatus != ERROR_SUCCESS && controlStatus != ERROR_WMI_INSTANCE_NOT_FOUND )
    {
        tracy_free( backup );
        tracy_free( s_propVsync );
        return;
    }

    memcpy( s_propVsync, backup, psz );
    tracy_free( backup );

    const auto startStatus = StartTraceA( &s_traceHandleVsync, "TracyVsync", s_propVsync );
    if( startStatus != ERROR_SUCCESS )
    {
        tracy_free( s_propVsync );
        return;
    }

    EVENT_FILTER_EVENT_ID fe = {};
    fe.FilterIn = TRUE;
    fe.Count = 1;
    fe.Events[0] = 0x0011;  // VSyncDPC_Info

    EVENT_FILTER_DESCRIPTOR desc = {};
    desc.Ptr = (ULONGLONG)&fe;
    desc.Size = sizeof( fe );
    desc.Type = EVENT_FILTER_TYPE_EVENT_ID;

    ENABLE_TRACE_PARAMETERS params = {};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    params.EnableProperty = EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0;
    params.SourceId = s_propVsync->Wnode.Guid;
    params.EnableFilterDesc = &desc;
    params.FilterDescCount = 1;

    uint64_t mask = 0x4000000000000001;   // Microsoft_Windows_DxgKrnl_Performance | Base
    if( EnableTraceEx2( s_traceHandleVsync, &DxgKrnlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, mask, mask, 0, &params ) != ERROR_SUCCESS )
    {
        tracy_free( s_propVsync );
        return;
    }

    char loggerName[MAX_PATH];
    strcpy( loggerName, "TracyVsync" );

    EVENT_TRACE_LOGFILEA log = {};
    log.LoggerName = loggerName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.EventRecordCallback = EventRecordCallbackVsync;

    s_traceHandleVsync2 = OpenTraceA( &log );
    if( s_traceHandleVsync2 == (TRACEHANDLE)INVALID_HANDLE_VALUE )
    {
        CloseTrace( s_traceHandleVsync );
        tracy_free( s_propVsync );
        return;
    }

    s_threadVsync = (Thread*)tracy_malloc( sizeof( Thread ) );
    new(s_threadVsync) Thread( [] (void*) {
        ThreadExitHandler threadExitHandler;
        SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL );
        SetThreadName( "Tracy Vsync" );
        ProcessTrace( &s_traceHandleVsync2, 1, nullptr, nullptr );
    }, nullptr );
#endif
}

bool SysTraceStart( int64_t& samplingPeriod )
{
    if( !_GetThreadDescription ) _GetThreadDescription = (t_GetThreadDescription)GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "GetThreadDescription" );

    s_pid = GetCurrentProcessId();

#if defined _WIN64
    constexpr bool isOs64Bit = true;
#else
    BOOL _iswow64;
    IsWow64Process( GetCurrentProcess(), &_iswow64 );
    const bool isOs64Bit = _iswow64;
#endif

    TOKEN_PRIVILEGES priv = {};
    priv.PrivilegeCount = 1;
    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if( LookupPrivilegeValue( nullptr, SE_SYSTEM_PROFILE_NAME, &priv.Privileges[0].Luid ) == 0 ) return false;

    HANDLE pt;
    if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &pt ) == 0 ) return false;
    const auto adjust = AdjustTokenPrivileges( pt, FALSE, &priv, 0, nullptr, nullptr );
    CloseHandle( pt );
    if( adjust == 0 ) return false;
    const auto status = GetLastError();
    if( status != ERROR_SUCCESS ) return false;

    if( isOs64Bit )
    {
        TRACE_PROFILE_INTERVAL interval = {};
        interval.Interval = 1250;   // 8 kHz
        const auto intervalStatus = TraceSetInformation( 0, TraceSampledProfileIntervalInfo, &interval, sizeof( interval ) );
        if( intervalStatus != ERROR_SUCCESS ) return false;
        samplingPeriod = 125*1000;
    }

    const auto psz = sizeof( EVENT_TRACE_PROPERTIES ) + sizeof( KERNEL_LOGGER_NAME );
    s_prop = (EVENT_TRACE_PROPERTIES*)tracy_malloc( psz );
    memset( s_prop, 0, sizeof( EVENT_TRACE_PROPERTIES ) );
    ULONG flags = 0;
#ifndef TRACY_NO_CONTEXT_SWITCH
    flags = EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_DISPATCHER | EVENT_TRACE_FLAG_THREAD;
#endif
#ifndef TRACY_NO_SAMPLING
    if( isOs64Bit ) flags |= EVENT_TRACE_FLAG_PROFILE;
#endif
    s_prop->EnableFlags = flags;
    s_prop->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    s_prop->Wnode.BufferSize = psz;
    s_prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
#ifdef TRACY_TIMER_QPC
    s_prop->Wnode.ClientContext = 1;
#else
    s_prop->Wnode.ClientContext = 3;
#endif
    s_prop->Wnode.Guid = SystemTraceControlGuid;
    s_prop->BufferSize = 1024;
    s_prop->MinimumBuffers = std::thread::hardware_concurrency() * 4;
    s_prop->MaximumBuffers = std::thread::hardware_concurrency() * 6;
    s_prop->LoggerNameOffset = sizeof( EVENT_TRACE_PROPERTIES );
    memcpy( ((char*)s_prop) + sizeof( EVENT_TRACE_PROPERTIES ), KERNEL_LOGGER_NAME, sizeof( KERNEL_LOGGER_NAME ) );

    auto backup = tracy_malloc( psz );
    memcpy( backup, s_prop, psz );

    const auto controlStatus = ControlTrace( 0, KERNEL_LOGGER_NAME, s_prop, EVENT_TRACE_CONTROL_STOP );
    if( controlStatus != ERROR_SUCCESS && controlStatus != ERROR_WMI_INSTANCE_NOT_FOUND )
    {
        tracy_free( backup );
        tracy_free( s_prop );
        return false;
    }

    memcpy( s_prop, backup, psz );
    tracy_free( backup );

    const auto startStatus = StartTrace( &s_traceHandle, KERNEL_LOGGER_NAME, s_prop );
    if( startStatus != ERROR_SUCCESS )
    {
        tracy_free( s_prop );
        return false;
    }

    if( isOs64Bit )
    {
        CLASSIC_EVENT_ID stackId;
        stackId.EventGuid = PerfInfoGuid;
        stackId.Type = 46;
        const auto stackStatus = TraceSetInformation( s_traceHandle, TraceStackTracingInfo, &stackId, sizeof( stackId ) );
        if( stackStatus != ERROR_SUCCESS )
        {
            tracy_free( s_prop );
            return false;
        }
    }

#ifdef UNICODE
    WCHAR KernelLoggerName[sizeof( KERNEL_LOGGER_NAME )];
#else
    char KernelLoggerName[sizeof( KERNEL_LOGGER_NAME )];
#endif
    memcpy( KernelLoggerName, KERNEL_LOGGER_NAME, sizeof( KERNEL_LOGGER_NAME ) );
    EVENT_TRACE_LOGFILE log = {};
    log.LoggerName = KernelLoggerName;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.EventRecordCallback = EventRecordCallback;

    s_traceHandle2 = OpenTrace( &log );
    if( s_traceHandle2 == (TRACEHANDLE)INVALID_HANDLE_VALUE )
    {
        CloseTrace( s_traceHandle );
        tracy_free( s_prop );
        return false;
    }

#ifndef TRACY_NO_VSYNC_CAPTURE
    SetupVsync();
#endif

    return true;
}

void SysTraceStop()
{
    if( s_threadVsync )
    {
        CloseTrace( s_traceHandleVsync2 );
        CloseTrace( s_traceHandleVsync );
        s_threadVsync->~Thread();
        tracy_free( s_threadVsync );
    }

    CloseTrace( s_traceHandle2 );
    CloseTrace( s_traceHandle );
}

void SysTraceWorker( void* ptr )
{
    ThreadExitHandler threadExitHandler;
    SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL );
    SetThreadName( "Tracy SysTrace" );
    ProcessTrace( &s_traceHandle2, 1, 0, 0 );
    ControlTrace( 0, KERNEL_LOGGER_NAME, s_prop, EVENT_TRACE_CONTROL_STOP );
    tracy_free( s_prop );
}

void SysTraceSendExternalName( uint64_t thread )
{
    bool threadSent = false;
    auto hnd = OpenThread( THREAD_QUERY_INFORMATION, FALSE, DWORD( thread ) );
    if( hnd == 0 )
    {
        hnd = OpenThread( THREAD_QUERY_LIMITED_INFORMATION, FALSE, DWORD( thread ) );
    }
    if( hnd != 0 )
    {
        PWSTR tmp;
        _GetThreadDescription( hnd, &tmp );
        char buf[256];
        if( tmp )
        {
            auto ret = wcstombs( buf, tmp, 256 );
            if( ret != 0 )
            {
                GetProfiler().SendString( thread, buf, ret, QueueType::ExternalThreadName );
                threadSent = true;
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
                    HMODULE modules[1024];
                    DWORD needed;
                    if( _EnumProcessModules( phnd, modules, 1024 * sizeof( HMODULE ), &needed ) != 0 )
                    {
                        const auto sz = std::min( DWORD( needed / sizeof( HMODULE ) ), DWORD( 1024 ) );
                        for( DWORD i=0; i<sz; i++ )
                        {
                            MODULEINFO info;
                            if( _GetModuleInformation( phnd, modules[i], &info, sizeof( info ) ) != 0 )
                            {
                                if( (uint64_t)ptr >= (uint64_t)info.lpBaseOfDll && (uint64_t)ptr <= (uint64_t)info.lpBaseOfDll + (uint64_t)info.SizeOfImage )
                                {
                                    char buf2[1024];
                                    const auto modlen = _GetModuleBaseNameA( phnd, modules[i], buf2, 1024 );
                                    if( modlen != 0 )
                                    {
                                        GetProfiler().SendString( thread, buf2, modlen, QueueType::ExternalThreadName );
                                        threadSent = true;
                                    }
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
            GetProfiler().SendString( thread, "???", 3, QueueType::ExternalThreadName );
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
                GetProfiler().SendString( thread, "System", 6, QueueType::ExternalName );
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
                        GetProfiler().SendString( thread, ptr, QueueType::ExternalName );
                        return;
                    }
                }
            }
        }
    }

    if( !threadSent )
    {
        GetProfiler().SendString( thread, "???", 3, QueueType::ExternalThreadName );
    }
    GetProfiler().SendString( thread, "???", 3, QueueType::ExternalName );
}

}

#  elif defined __linux__

#    include <sys/types.h>
#    include <sys/stat.h>
#    include <sys/wait.h>
#    include <fcntl.h>
#    include <inttypes.h>
#    include <limits>
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

#    include "TracyProfiler.hpp"
#    include "TracyRingBuffer.hpp"
#    include "TracyThread.hpp"

#    ifdef __ANDROID__
#      include "TracySysTracePayload.hpp"
#    endif

namespace tracy
{

static const char BasePath[] = "/sys/kernel/debug/tracing/";
static const char TracingOn[] = "tracing_on";
static const char CurrentTracer[] = "current_tracer";
static const char TraceOptions[] = "trace_options";
static const char TraceClock[] = "trace_clock";
static const char SchedSwitch[] = "events/sched/sched_switch/enable";
static const char SchedWakeup[] = "events/sched/sched_wakeup/enable";
static const char BufferSizeKb[] = "buffer_size_kb";
static const char TracePipe[] = "trace_pipe";

static std::atomic<bool> traceActive { false };
static Thread* s_threadSampling = nullptr;
static int s_numCpus = 0;

static constexpr size_t RingBufSize = 64*1024;
static RingBuffer<RingBufSize>* s_ring = nullptr;

static int perf_event_open( struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags )
{
    return syscall( __NR_perf_event_open, hw_event, pid, cpu, group_fd, flags );
}

static void SetupSampling( int64_t& samplingPeriod )
{
#ifndef CLOCK_MONOTONIC_RAW
    return;
#endif

    samplingPeriod = 100*1000;

    s_numCpus = (int)std::thread::hardware_concurrency();
    s_ring = (RingBuffer<RingBufSize>*)tracy_malloc( sizeof( RingBuffer<RingBufSize> ) * s_numCpus );

    perf_event_attr pe = {};

    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof( perf_event_attr );
    pe.config = PERF_COUNT_SW_CPU_CLOCK;

    pe.sample_freq = 10000;
    pe.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN;
#if LINUX_VERSION_CODE >= KERNEL_VERSION( 4, 8, 0 )
    pe.sample_max_stack = 127;
#endif
    pe.exclude_callchain_kernel = 1;

    pe.disabled = 1;
    pe.freq = 1;
#if !defined TRACY_HW_TIMER || !( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
    pe.use_clockid = 1;
    pe.clockid = CLOCK_MONOTONIC_RAW;
#endif

    for( int i=0; i<s_numCpus; i++ )
    {
        const int fd = perf_event_open( &pe, -1, i, -1, 0 );
        if( fd == -1 )
        {
            for( int j=0; j<i; j++ ) s_ring[j].~RingBuffer<RingBufSize>();
            tracy_free( s_ring );
            return;
        }
        new( s_ring+i ) RingBuffer<RingBufSize>( fd );
    }

    s_threadSampling = (Thread*)tracy_malloc( sizeof( Thread ) );
    new(s_threadSampling) Thread( [] (void*) {
        ThreadExitHandler threadExitHandler;
        SetThreadName( "Tracy Sampling" );
        sched_param sp = { 5 };
        pthread_setschedparam( pthread_self(), SCHED_FIFO, &sp );
        uint32_t currentPid = (uint32_t)getpid();
#if defined TRACY_HW_TIMER && ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
        for( int i=0; i<s_numCpus; i++ )
        {
            if( !s_ring[i].CheckTscCaps() )
            {
                for( int j=0; j<s_numCpus; j++ ) s_ring[j].~RingBuffer<RingBufSize>();
                tracy_free( s_ring );
                const char* err = "Tracy Profiler: sampling is disabled due to non-native scheduler clock. Are you running under a VM?";
                Profiler::MessageAppInfo( err, strlen( err ) );
                return;
            }
        }
#endif
        for( int i=0; i<s_numCpus; i++ ) s_ring[i].Enable();
        for(;;)
        {
            bool hadData = false;
            for( int i=0; i<s_numCpus; i++ )
            {
                if( !traceActive.load( std::memory_order_relaxed ) ) break;
                if( !s_ring[i].HasData() ) continue;
                hadData = true;

                perf_event_header hdr;
                s_ring[i].Read( &hdr, 0, sizeof( perf_event_header ) );
                if( hdr.type == PERF_RECORD_SAMPLE )
                {
                    uint32_t pid, tid;
                    uint64_t t0;
                    uint64_t cnt;

                    auto offset = sizeof( perf_event_header );
                    s_ring[i].Read( &pid, offset, sizeof( uint32_t ) );
                    if( pid == currentPid )
                    {
                        offset += sizeof( uint32_t );
                        s_ring[i].Read( &tid, offset, sizeof( uint32_t ) );
                        offset += sizeof( uint32_t );
                        s_ring[i].Read( &t0, offset, sizeof( uint64_t ) );
                        offset += sizeof( uint64_t );
                        s_ring[i].Read( &cnt, offset, sizeof( uint64_t ) );
                        offset += sizeof( uint64_t );

                        auto trace = (uint64_t*)tracy_malloc( ( 1 + cnt ) * sizeof( uint64_t ) );
                        s_ring[i].Read( trace+1, offset, sizeof( uint64_t ) * cnt );

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

                        // skip kernel frames
                        uint64_t j;
                        for( j=0; j<cnt; j++ )
                        {
                            if( (int64_t)trace[j+1] >= 0 ) break;
                        }
                        if( j == cnt )
                        {
                            tracy_free( trace );
                        }
                        else
                        {
                            if( j > 0 )
                            {
                                cnt -= j;
                                memmove( trace+1, trace+1+j, sizeof( uint64_t ) * cnt );
                            }
                            memcpy( trace, &cnt, sizeof( uint64_t ) );

#if defined TRACY_HW_TIMER && ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
                            t0 = s_ring[i].ConvertTimeToTsc( t0 );
#endif

                            TracyLfqPrepare( QueueType::CallstackSample );
                            MemWrite( &item->callstackSampleFat.time, t0 );
                            MemWrite( &item->callstackSampleFat.thread, (uint64_t)tid );
                            MemWrite( &item->callstackSampleFat.ptr, (uint64_t)trace );
                            TracyLfqCommit;
                        }
                    }
                }
                s_ring[i].Advance( hdr.size );
            }
            if( !traceActive.load( std::memory_order_relaxed) ) break;
            if( !hadData )
            {
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }
        }

        for( int i=0; i<s_numCpus; i++ ) s_ring[i].~RingBuffer<RingBufSize>();
        tracy_free( s_ring );
    }, nullptr );
}

#ifdef __ANDROID__
static bool TraceWrite( const char* path, size_t psz, const char* val, size_t vsz )
{
    // Explanation for "su root sh -c": there are 2 flavors of "su" in circulation
    // on Android. The default Android su has the following syntax to run a command
    // as root:
    //   su root 'command'
    // and 'command' is exec'd not passed to a shell, so if shell interpretation is
    // wanted, one needs to do:
    //   su root sh -c 'command'
    // Besides that default Android 'su' command, some Android devices use a different
    // su with a command-line interface closer to the familiar util-linux su found
    // on Linux distributions. Fortunately, both the util-linux su and the one
    // in https://github.com/topjohnwu/Magisk seem to be happy with the above
    // `su root sh -c 'command'` command line syntax.
    char tmp[256];
    sprintf( tmp, "su root sh -c 'echo \"%s\" > %s%s'", val, BasePath, path );
    return system( tmp ) == 0;
}
#else
static bool TraceWrite( const char* path, size_t psz, const char* val, size_t vsz )
{
    char tmp[256];
    memcpy( tmp, BasePath, sizeof( BasePath ) - 1 );
    memcpy( tmp + sizeof( BasePath ) - 1, path, psz );

    int fd = open( tmp, O_WRONLY );
    if( fd < 0 ) return false;

    for(;;)
    {
        ssize_t cnt = write( fd, val, vsz );
        if( cnt == (ssize_t)vsz )
        {
            close( fd );
            return true;
        }
        if( cnt < 0 )
        {
            close( fd );
            return false;
        }
        vsz -= cnt;
        val += cnt;
    }
}
#endif

#ifdef __ANDROID__
void SysTraceInjectPayload()
{
    int pipefd[2];
    if( pipe( pipefd ) == 0 )
    {
        const auto pid = fork();
        if( pid == 0 )
        {
            // child
            close( pipefd[1] );
            if( dup2( pipefd[0], STDIN_FILENO ) >= 0 )
            {
                close( pipefd[0] );
                execlp( "su", "su", "root", "sh", "-c", "cat > /data/tracy_systrace", (char*)nullptr );
                exit( 1 );
            }
        }
        else if( pid > 0 )
        {
            // parent
            close( pipefd[0] );

#ifdef __aarch64__
            write( pipefd[1], tracy_systrace_aarch64_data, tracy_systrace_aarch64_size );
#else
            write( pipefd[1], tracy_systrace_armv7_data, tracy_systrace_armv7_size );
#endif
            close( pipefd[1] );
            waitpid( pid, nullptr, 0 );

            system( "su root sh -c 'chmod 700 /data/tracy_systrace'" );
        }
    }
}
#endif

bool SysTraceStart( int64_t& samplingPeriod )
{
#ifndef CLOCK_MONOTONIC_RAW
    return false;
#endif

    if( !TraceWrite( TracingOn, sizeof( TracingOn ), "0", 2 ) ) return false;
    if( !TraceWrite( CurrentTracer, sizeof( CurrentTracer ), "nop", 4 ) ) return false;
    TraceWrite( TraceOptions, sizeof( TraceOptions ), "norecord-cmd", 13 );
    TraceWrite( TraceOptions, sizeof( TraceOptions ), "norecord-tgid", 14 );
    TraceWrite( TraceOptions, sizeof( TraceOptions ), "noirq-info", 11 );
    TraceWrite( TraceOptions, sizeof( TraceOptions ), "noannotate", 11 );
#if defined TRACY_HW_TIMER && ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
    if( !TraceWrite( TraceClock, sizeof( TraceClock ), "x86-tsc", 8 ) ) return false;
#else
    if( !TraceWrite( TraceClock, sizeof( TraceClock ), "mono_raw", 9 ) ) return false;
#endif
    if( !TraceWrite( SchedSwitch, sizeof( SchedSwitch ), "1", 2 ) ) return false;
    if( !TraceWrite( SchedWakeup, sizeof( SchedWakeup ), "1", 2 ) ) return false;
    if( !TraceWrite( BufferSizeKb, sizeof( BufferSizeKb ), "4096", 5 ) ) return false;

#if defined __ANDROID__ && ( defined __aarch64__ || defined __ARM_ARCH )
    SysTraceInjectPayload();
#endif

    if( !TraceWrite( TracingOn, sizeof( TracingOn ), "1", 2 ) ) return false;
    traceActive.store( true, std::memory_order_relaxed );

    SetupSampling( samplingPeriod );

    return true;
}

void SysTraceStop()
{
    TraceWrite( TracingOn, sizeof( TracingOn ), "0", 2 );
    traceActive.store( false, std::memory_order_relaxed );
    if( s_threadSampling )
    {
        s_threadSampling->~Thread();
        tracy_free( s_threadSampling );
    }
}

static uint64_t ReadNumber( const char*& data )
{
    auto ptr = data;
    assert( *ptr >= '0' && *ptr <= '9' );
    uint64_t val = *ptr++ - '0';
    for(;;)
    {
        const uint8_t v = uint8_t( *ptr - '0' );
        if( v > 9 ) break;
        val = val * 10 + v;
        ptr++;
    }
    data = ptr;
    return val;
}

static uint8_t ReadState( char state )
{
    switch( state )
    {
    case 'D': return 101;
    case 'I': return 102;
    case 'R': return 103;
    case 'S': return 104;
    case 'T': return 105;
    case 't': return 106;
    case 'W': return 107;
    case 'X': return 108;
    case 'Z': return 109;
    default: return 100;
    }
}

#if defined __ANDROID__ && defined __ANDROID_API__ && __ANDROID_API__ < 18
/*-
 * Copyright (c) 2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

ssize_t getdelim(char **buf, size_t *bufsiz, int delimiter, FILE *fp)
{
	char *ptr, *eptr;

	if (*buf == NULL || *bufsiz == 0) {
		*bufsiz = BUFSIZ;
		if ((*buf = (char*)malloc(*bufsiz)) == NULL)
			return -1;
	}

	for (ptr = *buf, eptr = *buf + *bufsiz;;) {
		int c = fgetc(fp);
		if (c == -1) {
			if (feof(fp))
				return ptr == *buf ? -1 : ptr - *buf;
			else
				return -1;
		}
		*ptr++ = c;
		if (c == delimiter) {
			*ptr = '\0';
			return ptr - *buf;
		}
		if (ptr + 2 >= eptr) {
			char *nbuf;
			size_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			if ((nbuf = (char*)realloc(*buf, nbufsiz)) == NULL)
				return -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

ssize_t getline(char **buf, size_t *bufsiz, FILE *fp)
{
	return getdelim(buf, bufsiz, '\n', fp);
}
#endif

static void HandleTraceLine( const char* line )
{
    line += 23;
    while( *line != '[' ) line++;
    line++;
    const auto cpu = (uint8_t)ReadNumber( line );
    line++;      // ']'
    while( *line == ' ' ) line++;

#if defined TRACY_HW_TIMER && ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
    const auto time = ReadNumber( line );
#else
    const auto ts = ReadNumber( line );
    line++;      // '.'
    const auto tus = ReadNumber( line );
    const auto time = ts * 1000000000ll + tus * 1000ll;
#endif

    line += 2;   // ': '
    if( memcmp( line, "sched_switch", 12 ) == 0 )
    {
        line += 14;

        while( memcmp( line, "prev_pid", 8 ) != 0 ) line++;
        line += 9;

        const auto oldPid = ReadNumber( line );
        line++;

        while( memcmp( line, "prev_state", 10 ) != 0 ) line++;
        line += 11;

        const auto oldState = (uint8_t)ReadState( *line );
        line += 5;

        while( memcmp( line, "next_pid", 8 ) != 0 ) line++;
        line += 9;

        const auto newPid = ReadNumber( line );

        uint8_t reason = 100;

        TracyLfqPrepare( QueueType::ContextSwitch );
        MemWrite( &item->contextSwitch.time, time );
        MemWrite( &item->contextSwitch.oldThread, oldPid );
        MemWrite( &item->contextSwitch.newThread, newPid );
        MemWrite( &item->contextSwitch.cpu, cpu );
        MemWrite( &item->contextSwitch.reason, reason );
        MemWrite( &item->contextSwitch.state, oldState );
        TracyLfqCommit;
    }
    else if( memcmp( line, "sched_wakeup", 12 ) == 0 )
    {
        line += 14;

        while( memcmp( line, "pid=", 4 ) != 0 ) line++;
        line += 4;

        const auto pid = ReadNumber( line );

        TracyLfqPrepare( QueueType::ThreadWakeup );
        MemWrite( &item->threadWakeup.time, time );
        MemWrite( &item->threadWakeup.thread, pid );
        TracyLfqCommit;
    }
}

#ifdef __ANDROID__
static void ProcessTraceLines( int fd )
{
    // Linux pipe buffer is 64KB, additional 1KB is for unfinished lines
    char* buf = (char*)tracy_malloc( (64+1)*1024 );
    char* line = buf;

    for(;;)
    {
        if( !traceActive.load( std::memory_order_relaxed ) ) break;

        const auto rd = read( fd, line, 64*1024 );
        if( rd <= 0 ) break;

#ifdef TRACY_ON_DEMAND
        if( !GetProfiler().IsConnected() )
        {
            if( rd < 64*1024 )
            {
                assert( line[rd-1] == '\n' );
                line = buf;
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }
            else
            {
                const auto end = line + rd;
                line = end - 1;
                while( line > buf && *line != '\n' ) line--;
                if( line > buf )
                {
                    line++;
                    const auto lsz = end - line;
                    memmove( buf, line, lsz );
                    line = buf + lsz;
                }
            }
            continue;
        }
#endif

        const auto end = line + rd;
        line = buf;
        for(;;)
        {
            auto next = (char*)memchr( line, '\n', end - line );
            if( !next )
            {
                const auto lsz = end - line;
                memmove( buf, line, lsz );
                line = buf + lsz;
                break;
            }
            HandleTraceLine( line );
            line = ++next;
        }
        if( rd < 64*1024 )
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
        }
    }

    tracy_free( buf );
}

void SysTraceWorker( void* ptr )
{
    ThreadExitHandler threadExitHandler;
    SetThreadName( "Tracy SysTrace" );
    int pipefd[2];
    if( pipe( pipefd ) == 0 )
    {
        const auto pid = fork();
        if( pid == 0 )
        {
            // child
            close( pipefd[0] );
            dup2( open( "/dev/null", O_WRONLY ), STDERR_FILENO );
            if( dup2( pipefd[1], STDOUT_FILENO ) >= 0 )
            {
                close( pipefd[1] );
                sched_param sp = { 4 };
                pthread_setschedparam( pthread_self(), SCHED_FIFO, &sp );
#if defined __ANDROID__ && ( defined __aarch64__ || defined __ARM_ARCH )
                execlp( "su", "su", "root", "sh", "-c", "/data/tracy_systrace", (char*)nullptr );
#endif
                execlp( "su", "su", "root", "sh", "-c", "cat /sys/kernel/debug/tracing/trace_pipe", (char*)nullptr );
                exit( 1 );
            }
        }
        else if( pid > 0 )
        {
            // parent
            close( pipefd[1] );
            sched_param sp = { 5 };
            pthread_setschedparam( pthread_self(), SCHED_FIFO, &sp );
            ProcessTraceLines( pipefd[0] );
            close( pipefd[0] );
            waitpid( pid, nullptr, 0 );
        }
    }
}
#else
static void ProcessTraceLines( int fd )
{
    char* buf = (char*)tracy_malloc( 64*1024 );

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN | POLLERR;

    for(;;)
    {
        while( poll( &pfd, 1, 0 ) <= 0 )
        {
            if( !traceActive.load( std::memory_order_relaxed ) ) break;
            std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
        }

        const auto rd = read( fd, buf, 64*1024 );
        if( rd <= 0 ) break;

#ifdef TRACY_ON_DEMAND
        if( !GetProfiler().IsConnected() ) continue;
#endif

        auto line = buf;
        const auto end = buf + rd;
        for(;;)
        {
            auto next = (char*)memchr( line, '\n', end - line );
            if( !next ) break;
            HandleTraceLine( line );
            line = ++next;
        }
    }

    tracy_free( buf );
}

void SysTraceWorker( void* ptr )
{
    ThreadExitHandler threadExitHandler;
    SetThreadName( "Tracy SysTrace" );
    char tmp[256];
    memcpy( tmp, BasePath, sizeof( BasePath ) - 1 );
    memcpy( tmp + sizeof( BasePath ) - 1, TracePipe, sizeof( TracePipe ) );

    int fd = open( tmp, O_RDONLY );
    if( fd < 0 ) return;
    sched_param sp = { 5 };
    pthread_setschedparam( pthread_self(), SCHED_FIFO, &sp );
    ProcessTraceLines( fd );
    close( fd );
}
#endif

void SysTraceSendExternalName( uint64_t thread )
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
        GetProfiler().SendString( thread, buf, QueueType::ExternalThreadName );
        fclose( f );
    }
    else
    {
        GetProfiler().SendString( thread, "???", 3, QueueType::ExternalThreadName );
    }

    sprintf( fn, "/proc/%" PRIu64 "/status", thread );
    f = fopen( fn, "rb" );
    if( f )
    {
        int pid = -1;
        size_t lsz = 1024;
        auto line = (char*)tracy_malloc( lsz );
        for(;;)
        {
            auto rd = getline( &line, &lsz, f );
            if( rd <= 0 ) break;
            if( memcmp( "Tgid:\t", line, 6 ) == 0 )
            {
                pid = atoi( line + 6 );
                break;
            }
        }
        tracy_free( line );
        fclose( f );
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
                GetProfiler().SendString( thread, buf, QueueType::ExternalName );
                fclose( f );
                return;
            }
        }
    }
    GetProfiler().SendString( thread, "???", 3, QueueType::ExternalName );
}

}

#  endif

#endif
