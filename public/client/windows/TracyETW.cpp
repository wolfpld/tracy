#include <windows.h>
#include <guiddef.h>
#include <evntcons.h>
#include <evntrace.h>

#include <stdio.h>
#include <thread>

namespace tracy
{
namespace etw
{

constexpr GUID NullGuid      = {};
constexpr GUID ThreadGuid    = { 0x3D6FA8D1, 0xFE05, 0x11D0, { 0x9D, 0xDA, 0x00, 0xC0, 0x4F, 0xD7, 0xBA, 0x7C } };
constexpr GUID PerfInfoGuid  = { 0xCE1DBFB4, 0x137E, 0x4DA6, { 0x87, 0xB0, 0x3F, 0x59, 0xAA, 0x10, 0x2C, 0xBC } };
constexpr GUID StackWalkGuid = { 0xDEF2FE46, 0x7BD6, 0x4B80, { 0xBD, 0x94, 0xF5, 0x7F, 0xE2, 0x0D, 0x0C, 0xE3 } };
constexpr GUID DxgKrnlGuid   = { 0x802EC45A, 0x1E99, 0x4B83, { 0x99, 0x20, 0x87, 0xC9, 0x82, 0x77, 0xBA, 0x9D } };
constexpr GUID LostEventGuid = { 0x6A399AE0, 0x4BC6, 0x4DE9, { 0x87, 0x0B, 0x36, 0x57, 0xF8, 0x94, 0x7E, 0x7E } };

struct Session
{
    EVENT_TRACE_PROPERTIES properties = {};
    CHAR name[64] = {};
    CONTROLTRACE_ID handle = 0;
};

static void ETWErrorAction( ULONG error_code, const char* message, int length )
{
#ifdef TRACY_HAS_CALLSTACK
    tracy::InitCallstackCritical();
    TracyMessageCS( message, length, tracy::Color::Red4, 60 );
#else
    TracyMessageC( message, length, tracy::Color::Red4 );
#endif
#ifdef __cpp_exceptions
    // TODO: should we throw an exception?
#endif
}

static ULONG ETWError( ULONG result )
{
    if( result == ERROR_SUCCESS )
        return result;
    ZoneScopedC( tracy::Color::Red4 );
    char message[128] = {};
    int written = snprintf( message, sizeof( message ), "ETW Error %u (0x%x): ", result, result );
    written += FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        result,
        MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
        (LPSTR)&message[written],
        sizeof( message ) - written,
        NULL );
    ETWErrorAction( result, message, written );
    return result;
}

static DWORD ElevatePrivilege( LPCTSTR PrivilegeName )
{
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if( LookupPrivilegeValue( nullptr, PrivilegeName, &tp.Privileges[0].Luid ) == FALSE )
        return ETWError( GetLastError() );
    HANDLE hToken = {};
    if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken ) == FALSE )
        return ETWError( GetLastError() );
    BOOL adjusted = AdjustTokenPrivileges( hToken, FALSE, &tp, 0, nullptr, nullptr );
    DWORD status = GetLastError();
    CloseHandle( hToken );    // NOTE: skipping error handling for CloseHandle()
    return ETWError( status );
}

static ULONG StartSession( Session& session )
{
    ULONG status = StartTraceA( &session.handle, session.name, &session.properties );
    if( status == ERROR_ALREADY_EXISTS )
    {
        // Session is already running (likely from a previous run that did not terminate
        // gracefully). There are two options: take control of the existing session with
        // ControlSession(UPDATE), or stop the session and start fresh again. The latter
        // is better because it also resets the event providers.
        status = ControlTraceA( session.handle, session.name, &session.properties, EVENT_TRACE_CONTROL_STOP );
        if( status != ERROR_SUCCESS )
            return ETWError( status );
        status = StartTraceA( &session.handle, session.name, &session.properties );
    }
    return ETWError( status );
}

static ULONG StopSession( Session& session )
{
    ULONG status = ControlTraceA( session.handle, session.name, &session.properties, EVENT_TRACE_CONTROL_STOP );
    if( status != ERROR_SUCCESS )
        return ETWError( status );
    // once stopped, the session handle becomes invalid
    session.handle = 0;
    return ERROR_SUCCESS;
}

static ULONG EnableProvider(
    Session& session,
    const GUID& ProviderId,
    ULONG ControlCode = EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    UCHAR Level = TRACE_LEVEL_INFORMATION,
    ULONGLONG MatchAnyKeyword = 0,  // NOTE: a MatchAnyKeyword of 0 actually means "all bits set", according to the EnableTraceEx2 docs
    ULONGLONG MatchAllKeyword = 0,
    ULONG Timeout = 0,
    PENABLE_TRACE_PARAMETERS EnableParameters = NULL )
{
    ULONG status = EnableTraceEx2( session.handle, &ProviderId, ControlCode, Level, MatchAnyKeyword, MatchAllKeyword, Timeout, EnableParameters );
    return ETWError( status );
}

static ULONG EnableStackWalk( Session& session, GUID EventGuid, UCHAR Opcode )
{
#if defined _WIN64
    constexpr bool isOs64Bit = true;
#else
    BOOL _iswow64;
    IsWow64Process( GetCurrentProcess(), &_iswow64 );
    const bool isOs64Bit = _iswow64;
#endif
    if( !isOs64Bit )
        return 0 /* ERROR_SUCCESS */;   // TODO: return error instead?
    CLASSIC_EVENT_ID stackId[1] = {};
    stackId[0].EventGuid = EventGuid;
    stackId[0].Type = Opcode;
    ULONG status = TraceSetInformation( session.handle, TraceStackTracingInfo, &stackId, sizeof( stackId ) );
    return ETWError( status );
}

static Session StartPrivateKernelSession( const CHAR* name )
{
    Session session = {};

    size_t maxlen = sizeof( session.name );
    for( size_t i = 0; i < maxlen && name[i] != 0; ++i )
    {
        session.name[i] = name[i];
    }

    auto& props = session.properties;
    props.LoggerNameOffset = offsetof( Session, name );
    props.Wnode.BufferSize = sizeof( Session );
    props.Wnode.Guid = NullGuid;
#ifdef TRACY_TIMER_QPC
    props.Wnode.ClientContext = 1;  // 1: QueryPerformanceCounter
#else
    props.Wnode.ClientContext = 3;  // 3: CPU Ticks (e.g., rdtsc)
#endif
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
    props.LogFileMode |= EVENT_TRACE_REAL_TIME_MODE;

    // TODO: should we really be tweaking the buffering parameters?
    props.BufferSize = 1024;
    props.MinimumBuffers = std::thread::hardware_concurrency() * 4;
    props.MaximumBuffers = std::thread::hardware_concurrency() * 6;

    ULONG status = StartSession( session );
    if( status != ERROR_SUCCESS )
        return {};

    return session;
}

static ULONG EnableProcessAndThreadMonitoring(Session& session) {
    ULONGLONG MatchAnyKeyword = SYSTEM_PROCESS_KW_THREAD;   // ThreadStart and ThreadDCStart events
    ULONG status = EnableProvider( session, SystemProcessProviderGuid,
                                   EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, MatchAnyKeyword );
    if (status != ERROR_SUCCESS)
        return status;
    return status;
}

static ULONG EnableCPUProfiling( Session& session, int microseconds = 125 /* 8KHz = 125us */ )
{
    // CPU Profiling requires special privileges on top of admin privileges
    DWORD access = ElevatePrivilege( SE_SYSTEM_PROFILE_NAME );
    if( access != ERROR_SUCCESS )
        return access;

    ULONG status = EnableProvider( session, SystemProfileProviderGuid );
    if( status != ERROR_SUCCESS )
        return status;

    TRACE_PROFILE_INTERVAL interval = {};
    interval.Source = 0; // 0: ProfileTime
    interval.Interval = ( microseconds * 1000 ) / 100; // in 100's of nanoseconds
    CONTROLTRACE_ID TraceId = 0; // must be zero for TraceSampledProfileIntervalInfo
    status = TraceSetInformation( TraceId, TraceSampledProfileIntervalInfo, &interval, sizeof( interval ) );
    if( status != ERROR_SUCCESS )
        return ETWError( status );

    status = EnableStackWalk( session, PerfInfoGuid, 46 );  // PerfInfoGuid Opcode 46: SampledProfile event
    return status;
}

static ULONG EnableContextSwitchMonitoring( Session& session )
{
    ULONGLONG MatchAnyKeyword = 0;
    MatchAnyKeyword |= SYSTEM_SCHEDULER_KW_CONTEXT_SWITCH;  // CSwitch events
    MatchAnyKeyword |= SYSTEM_SCHEDULER_KW_DISPATCHER;      // ReadyThread events
    ULONG status = EnableProvider( session, SystemSchedulerProviderGuid,
                                   EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, MatchAnyKeyword );
    if( status != ERROR_SUCCESS )
        return status;
    status = EnableStackWalk( session, ThreadGuid, 36 );  // ThreadGuid Opcode 36: CSwitch event
    return status;
}

static ULONG EnableVSyncMonitoring( Session& session )
{
// TODO: is this correct?
#if ( _WIN32_WINNT < _WIN32_WINNT_WINBLUE ) || defined( __MINGW32__ )
    return ETWError( ERROR_NOT_SUPPORTED );
#endif

    enum Keyword : ULONGLONG
    {
        DxgKrnlBase    = 0x0000'0000'0000'0001, // Microsoft-Windows-DxgKrnl: Base
        DxgKrnlPresent = 0x0000'0000'0800'0000, // Microsoft-Windows-DxgKrnl: Present
        MSFTReserved62 = 0x4000'0000'0000'0000  // winmeta.h: WINEVENT_KEYWORD_RESERVED_62
                                                // (Microsoft-Windows-DxgKrnl/Performance, according to logman)
    };
    ULONGLONG MatchAnyKeyword = Keyword::MSFTReserved62 | Keyword::DxgKrnlPresent | Keyword::DxgKrnlBase;
    ULONGLONG MatchAllKeyword = MatchAnyKeyword;

    EVENT_FILTER_EVENT_ID fe = {};
    fe.FilterIn = TRUE;
    fe.Count = 1;
    fe.Events[0] = 0x0011;  // 0x11 = 17 : VSyncDPC_Info
    EVENT_FILTER_DESCRIPTOR desc = {};
    desc.Ptr = (ULONGLONG)&fe;
    desc.Size = sizeof( fe );
    desc.Type = EVENT_FILTER_TYPE_EVENT_ID;
    ENABLE_TRACE_PARAMETERS EnableParameters = {};
    EnableParameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    EnableParameters.EnableProperty = EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0;
    EnableParameters.SourceId = DxgKrnlGuid;    // or NullGuid? Does it even matter?
    EnableParameters.EnableFilterDesc = &desc;
    EnableParameters.FilterDescCount = 1;

    ULONG status = EnableProvider( session, DxgKrnlGuid,
                                   EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                                   MatchAnyKeyword, MatchAllKeyword, 0, &EnableParameters );
    return status;
}

static ULONG WINAPI OnBufferComplete( PEVENT_TRACE_LOGFILEA Buffer )
{
    if( Buffer->EventsLost > 0 )
    {
        char buffer[64] = {};
        int length = snprintf( buffer, sizeof( buffer ), "ETW Warning: %u events have been lost.", Buffer->EventsLost );
        ETWErrorAction( ERROR_BUFFER_OVERFLOW, buffer, length );
    }
    return TRUE;    // or FALSE to break out of ProcessTrace()
}

static PROCESSTRACE_HANDLE SetupEventConsumer( const Session& session, PEVENT_RECORD_CALLBACK callback )
{
    EVENT_TRACE_LOGFILEA trace = {};
    trace.LoggerName = (LPSTR)session.name;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME;
    trace.ProcessTraceMode |= PROCESS_TRACE_MODE_EVENT_RECORD;  // request EVENT_RECORD, not EVENT_TRACE (legacy)
    trace.ProcessTraceMode |= PROCESS_TRACE_MODE_RAW_TIMESTAMP; // no timestamp conversions (use whatever the session is using)
    trace.EventRecordCallback = callback;
    trace.BufferCallback = OnBufferComplete;

    PROCESSTRACE_HANDLE hConsumer = OpenTraceA( &trace );
    if( hConsumer == INVALID_PROCESSTRACE_HANDLE )
        ETWError( GetLastError() );

    return hConsumer;
}

static ULONG StopEventConsumer( PROCESSTRACE_HANDLE hEventConsumer )
{
    ULONG status = CloseTrace( hEventConsumer );
    if ((status != ERROR_SUCCESS) && (status != ERROR_CTX_CLOSE_PENDING))
        return ETWError( status );
    return status;
}

static ULONG EventConsumerLoop( PROCESSTRACE_HANDLE hEventConsumer )
{
    ULONG status = ProcessTrace( &hEventConsumer, 1, NULL, NULL );
    if( status != ERROR_SUCCESS && status != ERROR_CANCELLED )
        return ETWError( status );
    return status;
}

struct CSwitch
{
    // V2 fields:
    static constexpr UCHAR Opcode = 36;
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
static_assert(sizeof(CSwitch) == 24, "unexpected CSwitch struct size/alignment");

struct ReadyThread
{
    // V2 fields:
    static constexpr UCHAR Opcode = 50;
    uint32_t    threadId;
    int8_t      adjustReason;
    int8_t      adjustIncrement;
    int8_t      flag;
    int8_t      reserverd;
};
static_assert(sizeof(ReadyThread) == 8, "unexpected ReadyThread struct size/alignment");

struct ThreadInfo
{
    // V0 (Thread_V0_TypeGroup1) fields:
    uint32_t processId;
    uint32_t threadId;
    // NOTE: we only care about PID and TID for now, and these two are "invariant"
    // across all revisions (versions) of this event. As such, let's omit the other
    // fields since they vary based on the event version; their sizes also vary by
    // target architecture (32bit or 64bit), and this is not even mentioned in the
    // MSDN documentation, and worse, have not been updated in the official schemas
    // either (which ETW Explorer uses), but can be introspected via the TDH API.
};
static_assert(sizeof(ThreadInfo) == 8, "unexpected ThreadInfo struct size/alignment");

struct ThreadStart : public ThreadInfo
{
    static constexpr UCHAR Opcode = 1;
};
static_assert(sizeof(ThreadStart) == 8, "unexpected ThreadStart struct size/alignment");

// DC: Data Collection (associated with the "rundown" phase)
struct ThreadDCStart : public ThreadInfo
{
    static constexpr UCHAR Opcode = 3;
};
static_assert(sizeof(ThreadDCStart) == 8, "unexpected ThreadDCStart struct size/alignment");

struct StackWalkEvent
{
    // V2 fields:
    static constexpr UCHAR Opcode = 32;
    uint64_t eventTimeStamp;
    uint32_t stackProcess;
    uint32_t stackThread;
    uint64_t stack[192];    // arbitrary upperbound limit; schema stops at [32]
};
static_assert(offsetof(StackWalkEvent, stackProcess) == 8, "unexpected StackWalkEvent struct size/alignment");
static_assert(offsetof(StackWalkEvent, stackThread) == 12, "unexpected StackWalkEvent struct size/alignment");
static_assert(offsetof(StackWalkEvent, stack) == 16, "unexpected StackWalkEvent struct size/alignment");

struct VSyncInfo
{
    static constexpr USHORT EventId = 17; // 0x11
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
static_assert(sizeof(VSyncInfo) == 64, "unexpected VSyncInfo struct size/alignment");

}
}
