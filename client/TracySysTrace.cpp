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

struct __declspec(uuid("{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}")) PERFINFOGUID;
static const auto PerfInfoGuid = __uuidof(PERFINFOGUID);

struct __declspec(uuid("{802EC45A-1E99-4B83-9920-87C98277BA9D}")) DXGKRNLGUID;
static const auto DxgKrnlGuid = __uuidof(DXGKRNLGUID);


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
    EnableTraceEx2( s_traceHandleVsync, &DxgKrnlGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, mask, mask, 0, &params );

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
#    include <stdarg.h>
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

#    include <functional>

#    include "TracyProfiler.hpp"
#    include "TracyRingBuffer.hpp"
#    include "TracyThread.hpp"

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

static void log_error_errno(const char* file, int line, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    char buf[256];
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    fprintf(stderr, "ERROR (%s:%d) %s (errno=%d, %s)\n",
            file, line, buf, errno, strerror(errno));
    fflush(stderr);
}

#define TRACY_LOG_ERROR_ERRNO(...) \
    ::tracy::log_error_errno(__FILE__, __LINE__, __VA_ARGS__)

static int perf_event_open( struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags )
{
    return syscall( __NR_perf_event_open, hw_event, pid, cpu, group_fd, flags );
}

namespace {

// Encapsulates a file descriptor and possibly a PID. Two modes:
//   Either (if pid==0) just a file that we opened in this process.
//   Or (if pid!=0) our end of a pipe to a subprocess (given by pid) where we
//     perform file I/O as root. 
struct Channel {
    int fd;
    int pid;
};

// File access mode: read-only or write-only.
enum class Mode {
    Read,
    Write
};

}  // end anonymous namespace

// Internal implementation helper for the Open() function.
// Just opens a file and return the descriptor - thin wrapper around open(2).
// Motivation: have a homogeneous interface with OpenAsRoot().
// `ch` is the output-parameter where we return the file descriptor.
static bool OpenInProcess(Mode mode, const char* filename, Channel* ch) {
    int fd = open(filename, mode == Mode::Read ? O_RDONLY : O_WRONLY);
    if (fd == -1) {
        // Don't log an error here, this is normal, it's what we have
        // OpenAsRoot as a fallback for.
        return false;
    }
    ch->fd = fd;
    ch->pid = 0;
    return true;
}

// Internal implementation helper for the Open() function.
// Opens a file that may require root privileges to access.
// Works by forking a subprocess where the actual file I/O is done
// as root (exec su), and transferring the data via a pipe to our
// process. The `ch` output parameter is populated with the file
// descriptor of our end of that pipe, and the pid of the subprocess.
static bool OpenAsRoot(Mode mode, const char* filename, Channel* ch) {
    int data_transfer_pipe[2];
    if( pipe( data_transfer_pipe ) == -1 )
    {
        return false;
    }
    int read_end = data_transfer_pipe[0];
    int write_end = data_transfer_pipe[1];
    int child_end = mode == Mode::Read ? write_end : read_end;
    int parent_end = mode == Mode::Read ? read_end : write_end;
        
    const int pid = fork();
    if (pid == -1) {
        return false;
    }

    if( pid == 0 )
    {
        // Child process.
        close( parent_end );
        // Redirect either standard input or standard output (depending on if we're
        // going to be reading from or writing to a file) to our end of the pipe.
        int fd_to_dup_to_child_end = mode == Mode::Read ? STDOUT_FILENO : STDIN_FILENO;
        if( dup2( child_end, fd_to_dup_to_child_end ) == -1 ) {
            return false;
        }
        close( child_end );
        char dd_arg[256];
        strcpy(dd_arg, mode == Mode::Read ? "if=" : "of=");
        strcpy(dd_arg + strlen(dd_arg), filename);
#ifdef __ANDROID__
        execlp( "su", "su", "root", "dd", dd_arg, "status=none", nullptr);
#else
        execlp( "sudo", "sudo", "-n", "dd", dd_arg, "status=none", nullptr);
#endif
        // The above exec only returns in case of failure. Since here we're in the
        // child process, we want any error to be fatal.
        exit( EXIT_FAILURE );
    }
    
    // Parent process.
    close( child_end );
    ch->fd = parent_end;
    ch->pid = pid;
    return true;
}

// Opens a file that might require root permissions to access.
// First tries to open it directly in-process, then tries OpenAsRoot,
// spawning a subprocess to perform the file I/O as root (exec su).
// The output-parameter `ch` is populated with the resulting opened
// file descriptor and the pid of the subprocess (or 0 if the file
// was just opened in-process). The output `ch` should be closed by
// the Close() function.
// The return value indicates success.
static bool Open(Mode mode, const char* filename, Channel* ch) {
    if (OpenInProcess(mode, filename, ch)) {
        return true;
    }
    if (OpenAsRoot(mode, filename, ch)) {
        return true;
    }
    return false;
}

// Internal implementation helper for Close().
// Waits for the process given by `pid` to terminate.
// The return value is true with the subprocess exited with
// EXIT_SUCCESS, false otherwise.
static bool WaitForSubprocess(int pid) {
    while(true) {
        int status = 0;
        if (waitpid(pid, &status, 0) == -1) {
            return false;
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status) == EXIT_SUCCESS;
        }
        if (WIFSIGNALED(status)) {
            return false;
        }
    }
}

// Closes a Channel `ch` that was previously opened by Open().
// In case of a subprocess channel (OpenAsRoot), this will first
// wait for that subprocess to terminate.
// The return value indicates success. In the case where a
// subprocess was used, any failure in the actual remote file I/O
// may only be reported here (so it's important to check this retval).
static bool Close(const Channel& ch) {
    if (close(ch.fd) == -1) {
        return false;
    }
    if (ch.pid) {
        if (!WaitForSubprocess(ch.pid)) {
            return false;
        }
    }
    return true;
}

// Internal implementation helper for WriteBufferToFile.
// Writes buffer contents (given by address `buf` and size `buf_size`) to
// the specified file descriptor (`fd`). Handles the case of `write` writing
// fewer bytes than requested.
static bool WriteBufferToFd(int fd, const void* buf, ssize_t buf_size) {
    const char* buf_ptr = static_cast<const char*>(buf);
    while( buf_size > 0 )
    {
        ssize_t write_retval = write( fd, buf_ptr, buf_size );
        if( write_retval < 0 )
        {
            return false;
        }
        buf_size -= write_retval;
        buf_ptr += write_retval;
    }
    assert(buf_size == 0);
    return true;
}

// Writes buffer contents (given by address `buf` and size `buf_size`) to
// the file given by `filename`. If opening the file in-process fails, this will attempt
// opening the file in a subprocess as root (so this allows writing to files
// requiring more permissions than the calling process has).
// The return value indicates success.
static bool WriteBufferToFile(const char* filename, const void* buf, ssize_t buf_size) {
    Channel ch;
    if (!Open(Mode::Write, filename, &ch)) {
        return false;
    }
    if (!WriteBufferToFd(ch.fd, buf, buf_size)) {
        return false;
    }
    if (!Close(ch)) {
        return false;
    }
    return true;
}

// Convenience overload: writes the specified string, without the terminating 0.
static bool WriteBufferToFile(const char* filename, const char* buf) {
    return WriteBufferToFile(filename, buf, strlen(buf));
}

// Opens the file given by `filename` for read, and passes the resulting file
// descriptor to the passed `read_function`, which must return `true` if and only
// if it succeeded. If opening the file in-process fails, this will attempt
// opening the file in a subprocess as root (so this allows reading files
// requiring more permissions than the calling process has).
// The return value indicates success.
static bool ReadFileWithFunction(const char* filename, const std::function<bool(int)> &read_function) {
    Channel ch;
    if (!Open(Mode::Read, filename, &ch)) {
        return false;
    }
    if (!read_function(ch.fd)) {
        return false;
    }
    if (!Close(ch)) {
        return false;
    }
    return true;
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

    WriteBufferToFile("/proc/sys/kernel/perf_event_paranoid", "0");

    for( int i=0; i<s_numCpus; i++ )
    {
        const int fd = perf_event_open( &pe, -1, i, -1, 0 );
        if( fd == -1 )
        {
            TRACY_LOG_ERROR_ERRNO("perf_event_open failed");
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
            if( !hadData )
            {
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }
        }

        for( int i=0; i<s_numCpus; i++ ) s_ring[i].~RingBuffer<RingBufSize>();
        tracy_free( s_ring );
    }, nullptr );
}

static bool TraceWrite( const char* path, const char* val )
{
    char tmp[256];
    memcpy( tmp, BasePath, sizeof( BasePath ) - 1 );
    memcpy( tmp + sizeof( BasePath ) - 1, path, strlen(path) + 1 );

    if (!WriteBufferToFile(tmp, val)) {
        TRACY_LOG_ERROR_ERRNO("failed to write to %s", tmp);
        return false;
    }

    return true;
}

bool SysTraceStart( int64_t& samplingPeriod )
{
#ifndef CLOCK_MONOTONIC_RAW
    return false;
#endif

    if( !TraceWrite( TracingOn, "0" ) ) return false;
    if( !TraceWrite( CurrentTracer, "nop" ) ) return false;
    if( !TraceWrite( TraceOptions, "norecord-cmd" ) ) return false;
    if( !TraceWrite( TraceOptions, "norecord-tgid" ) ) return false;
    if( !TraceWrite( TraceOptions, "noirq-info" ) ) return false;
    if( !TraceWrite( TraceOptions, "noannotate" ) ) return false;
#if defined TRACY_HW_TIMER && ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
    if( !TraceWrite( TraceClock, "x86-tsc" ) ) return false;
#else
    if( !TraceWrite( TraceClock, "mono_raw" ) ) return false;
#endif
    if( !TraceWrite( SchedSwitch, "1" ) ) return false;
    if( !TraceWrite( SchedWakeup, "1" ) ) return false;
    if( !TraceWrite( BufferSizeKb, "4096" ) ) return false;

    if( !TraceWrite( TracingOn, "1" ) ) return false;
    traceActive.store( true, std::memory_order_relaxed );

    SetupSampling( samplingPeriod );

    return true;
}

void SysTraceStop()
{
    TraceWrite( TracingOn, "0" );
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

        while( memcmp( line, "pid", 3 ) != 0 ) line++;
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
#endif

void SysTraceWorker( void* ptr )
{
    ThreadExitHandler threadExitHandler;
    SetThreadName( "Tracy SysTrace" );
    char tmp[256];
    memcpy( tmp, BasePath, sizeof( BasePath ) - 1 );
    memcpy( tmp + sizeof( BasePath ) - 1, TracePipe, sizeof( TracePipe ) );

    sched_param sp = { 5 };
    pthread_setschedparam( pthread_self(), SCHED_FIFO, &sp );

    ReadFileWithFunction(tmp, [](int fd) {
        ProcessTraceLines(fd);
        return true;  // ProcessTraceLines doesn't report errors.
    });
}

void SysTraceSendExternalName( uint64_t thread )
{
    char fn[256];
    sprintf( fn, "/proc/%" PRIu64 "/comm", thread );

    if (!ReadFileWithFunction(fn, [=](int fd){
        char buf[256];
        const auto sz = read( fd, buf, sizeof(buf) );
        if (sz == -1) {
            return false;
        }
        if( sz > 0 && buf[sz-1] == '\n' ) buf[sz-1] = '\0';
        GetProfiler().SendString( thread, buf, QueueType::ExternalThreadName );
        return true;
    })) {
        TRACY_LOG_ERROR_ERRNO("failed to read %s", fn);
        return;
    }

    sprintf( fn, "/proc/%" PRIu64 "/status", thread );
    if (!ReadFileWithFunction(fn, [=](int fd){
        FILE* f = fdopen(dup(fd), "rb");
        if (!f) {
            return false;
        }
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
            char fn[256];
            sprintf( fn, "/proc/%i/comm", pid );
            if (!ReadFileWithFunction(fn, [=](int fd){
                char buf[256];
                const auto sz = read( fd, buf, sizeof(buf));
                if (sz == -1) {
                    return false;
                }
                if( sz > 0 && buf[sz-1] == '\n' ) buf[sz-1] = '\0';
                GetProfiler().SendString( thread, buf, QueueType::ExternalName );
                return true;
            })) {
                TRACY_LOG_ERROR_ERRNO("failed to read %s", fn);
                return false;
            }
        }
        return true;
    })) {
        TRACY_LOG_ERROR_ERRNO("failed to read %s", fn);
        GetProfiler().SendString( thread, "???", 3, QueueType::ExternalName );
        return;
    }
}

}

#  endif

#endif
