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
    CLASSIC_EVENT_ID stackwalk[8] = {};
};

// ---- ETW Events ----------

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
static_assert( sizeof( CSwitch ) == 24, "unexpected CSwitch struct size/alignment" );

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
static_assert( sizeof( ReadyThread ) == 8, "unexpected ReadyThread struct size/alignment" );

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
static_assert( sizeof( ThreadInfo ) == 8, "unexpected ThreadInfo struct size/alignment" );

struct ThreadStart : public ThreadInfo
{
    static constexpr UCHAR Opcode = 1;
};
static_assert( sizeof( ThreadStart ) == 8, "unexpected ThreadStart struct size/alignment" );

// DC: Data Collection (associated with the "rundown" phase)
struct ThreadDCStart : public ThreadInfo
{
    static constexpr UCHAR Opcode = 3;
};
static_assert( sizeof( ThreadDCStart ) == 8, "unexpected ThreadDCStart struct size/alignment" );

struct SampledProfile
{
    static constexpr UCHAR Opcode = 46;
    // NOTE: we don't handle SampledProfile events directly; instead, we handle
    // the StackWalk event associated with each SampledProfile event. Just like
    // ThreadInfo, the data layout varies based on the target architecture, and
    // the MSDN documentation and schemas are outdated.
    //uint64_t instructionPointer;    // 32/64 bits
    //uint32_t threadId;
    //uint32_t count;                 // Not used.
};
static_assert( sizeof( SampledProfile ) == 1, "unexpected SampledProfile struct size/alignment" );

struct StackWalkEvent
{
    // V2 fields:
    static constexpr UCHAR Opcode = 32;
    uint64_t eventTimeStamp;
    uint32_t stackProcess;
    uint32_t stackThread;
    uint64_t stack[192];    // arbitrary upperbound limit; schema stops at [32]
};
static_assert( offsetof( StackWalkEvent, stackProcess ) == 8, "unexpected StackWalkEvent struct size/alignment" );
static_assert( offsetof( StackWalkEvent, stackThread ) == 12, "unexpected StackWalkEvent struct size/alignment" );
static_assert( offsetof( StackWalkEvent, stack ) == 16, "unexpected StackWalkEvent struct size/alignment" );

struct VSyncDPC
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
static_assert( sizeof( VSyncDPC ) == 64, "unexpected VSyncInfo struct size/alignment" );

// --------------------------

constexpr uint32_t Color_Red4 = 0x8b0000;   // TracyColor.hpp

static void ETWErrorAction( ULONG error_code, const char* message, int length )
{
#ifndef TRACY_NO_INTERNAL_MESSAGE
#  ifdef TRACY_HAS_CALLSTACK
    tracy::InitCallstackCritical();
    tracy::Profiler::LogString( MessageSourceType::Tracy, MessageSeverity::Error, Color_Red4, 60, length, message );
#  else
    tracy::Profiler::LogString( MessageSourceType::Tracy, MessageSeverity::Error, Color_Red4, 0, length, message );
#  endif
#endif
#ifdef __cpp_exceptions
    // TODO: should we throw an exception?
#endif
}

static ULONG ETWError( ULONG result )
{
    if( result == ERROR_SUCCESS )
        return result;
    static constexpr tracy::SourceLocationData srcLocHere{ nullptr, __FUNCTION__, __FILE__, __LINE__, Color_Red4 };
    tracy::ScopedZone ___tracy_scoped_zone( &srcLocHere, 0, true );
    char message[128] = {};
    int written = snprintf( message, sizeof( message ), "ETW Error %u (0x%x): ", result, result );
    written += FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        result,
        MAKELANGID( LANG_ENGLISH, SUBLANG_ENGLISH_US ),
        (LPSTR)&message[written],
        sizeof( message ) - written,
        NULL );
    ETWErrorAction( result, message, written );
    return result;
}

static bool CheckAdminPrivilege()
{
    HANDLE hToken = NULL;
    if( OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) == FALSE )
        return ETWError( GetLastError() ), false;
    TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
    DWORD ReturnLength = 0;
    if( GetTokenInformation( hToken, TokenElevationType, &elevationType, sizeof( elevationType ), &ReturnLength ) == FALSE )
        ETWError( GetLastError() ), false;
    CloseHandle( hToken );
    return ( elevationType == TokenElevationTypeFull );
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

static bool IsOS64Bit()
{
#if defined _WIN64
    constexpr bool isOs64Bit = true;
#else
    BOOL _iswow64;
    IsWow64Process( GetCurrentProcess(), &_iswow64 );
    const bool isOs64Bit = _iswow64;
#endif
    return isOs64Bit;
}

static ULONG StopSession( Session& session )
{
    // Use a copy of the session properties, because ControlTrace() will write stuff to it
    Session temp = session;
    ULONG status = ControlTraceA( temp.handle, temp.name, &temp.properties, EVENT_TRACE_CONTROL_STOP );
    if( status != ERROR_SUCCESS )
        return ETWError( status );
    // once stopped, the session handle becomes invalid
    session.handle = 0;
    for( auto&& sw : session.stackwalk )
        sw = {};
    return ERROR_SUCCESS;
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
        status = StopSession( session );
        if( status != ERROR_SUCCESS )
            return status;
        status = StartTraceA( &session.handle, session.name, &session.properties );
    }
    return ETWError( status );
}

static ULONG CheckProviderSessions( GUID provider, ULONGLONG MatchAnyKeyword )
{
    MatchAnyKeyword = ( MatchAnyKeyword != 0 ) ? MatchAnyKeyword : ~ULONGLONG( 0 );
    char buffer[4096] = {};
    auto Info = (PTRACE_GUID_INFO)buffer;
    ULONG ActualSize = 0;
    ULONG result = EnumerateTraceGuidsEx( TraceGuidQueryInfo, &provider, sizeof( provider ), Info, sizeof( buffer ), &ActualSize );
    if( result != ERROR_SUCCESS )
        return ETWError( result );
    TRACE_ENABLE_INFO sessions[8] = {};
    // Info->InstanceCount is typically 1, but can be more when the provider is registered from within a DLL
    for( ULONG i = 0, offset = 0; i < Info->InstanceCount; ++i )
    {
        auto instance = (PTRACE_PROVIDER_INSTANCE_INFO)&buffer[sizeof( *Info ) + offset];
        auto first = (PTRACE_ENABLE_INFO)&buffer[sizeof( *Info ) + offset + sizeof( *instance )];
        for( ULONG j = 0; j < instance->EnableCount; ++j )
        {
            auto session = &first[j];
            for( auto&& entry : sessions )
            {
                if( entry.LoggerId == session->LoggerId )
                    continue;
                if( entry.LoggerId != 0 )
                    continue;
                if( ( MatchAnyKeyword & session->MatchAnyKeyword ) != 0 )
                    entry = *session;
                break;
            }
        }
        offset += instance->NextOffset;
    }
    if( sessions[0].LoggerId == 0 )
        return ERROR_SUCCESS;
    int length = snprintf( buffer, sizeof( buffer ), "ETW Warning: provider (0x%08X) already enabled by other session(s); Tracy may miss events.", provider.Data1 );
    ETWErrorAction( 0, buffer, length );
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
    if( !IsOS64Bit() )
        return 0 /* ERROR_SUCCESS */;   // TODO: return error instead?
    // TraceStackTracingInfo: Turns on stack trace collection for the specified kernel events
    //                        for the specified logger. It also turns off stack tracing for
    //                        all kernel events not on this list, regardless of prior status.
    // NOTE: It'd be nice if we could rely on TraceQueryInformation(TraceStackTracingInfo)
    // to retrieve the list of the active stack trace event ids, but even though MSDN says
    // that it is possible, the query call returns ERROR_NOT_SUPPORTED...
    // Instead, we keep our own array of active stack trace event ids in the session object.
    for( auto&& sw : session.stackwalk )
    {
        if( !IsEqualGUID( sw.EventGuid, {} ) )
            continue;
        sw.EventGuid = EventGuid;
        sw.Type = Opcode;
        size_t count = ( &sw - session.stackwalk ) + 1;
        ULONG status = TraceSetInformation( session.handle, TraceStackTracingInfo, session.stackwalk, count * sizeof( CLASSIC_EVENT_ID ) );
        return ETWError( status );
    }
    return 0 /* ERROR_SUCCESS */;   // TODO: return error instead?
}

static ULONG SetCPUProfilingInterval( int microseconds )
{
    if( !IsOS64Bit() )
        return 0 /* ERROR_SUCCESS */;   // TODO: fabricate SetLastError(ERROR_NOT_SUPPORTED) instead?
    TRACE_PROFILE_INTERVAL interval = {};
    interval.Source = 0; // 0: ProfileTime (from enum KPROFILE_SOURCE in wdm.h)
    interval.Interval = ( microseconds * 1000 ) / 100; // in 100's of nanoseconds
    CONTROLTRACE_ID TraceId = 0; // must be zero for TraceSampledProfileIntervalInfo
    ULONG status = TraceSetInformation( TraceId, TraceSampledProfileIntervalInfo, &interval, sizeof( interval ) );
    return ETWError( status );
}

static Session StartSingletonKernelLoggerSession( ULONGLONG EnableFlags )
{
    Session session = {};

    size_t maxlen = sizeof( session.name ) - 1;
    strncpy( session.name, KERNEL_LOGGER_NAMEA, maxlen );
    session.name[maxlen] = '\0';

    auto& props = session.properties;
    props.LoggerNameOffset = offsetof( Session, name );
    props.Wnode.BufferSize = sizeof( Session );
    props.Wnode.Guid = SystemTraceControlGuid;
#ifdef TRACY_TIMER_QPC
    props.Wnode.ClientContext = 1;  // 1: QueryPerformanceCounter
#else
    props.Wnode.ClientContext = 3;  // 3: CPU Ticks (e.g., rdtsc)
#endif
    props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    props.EnableFlags = EnableFlags;

    // TODO: should we really be tweaking the buffering parameters?
    props.BufferSize = 1024;    // in KB
    props.MinimumBuffers = std::thread::hardware_concurrency() * 4;
    props.MaximumBuffers = std::thread::hardware_concurrency() * 6;

    ULONG status = StartSession( session );
    if( status != ERROR_SUCCESS )
        return {};

    return session;
}

static Session StartPrivateKernelSession( const CHAR* name )
{
    Session session = {};

    size_t maxlen = sizeof( session.name ) - 1;
    strncpy( session.name, name, maxlen );
    session.name[maxlen] = '\0';

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
    props.LogFileMode = 0;
    props.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
    props.LogFileMode |= EVENT_TRACE_REAL_TIME_MODE;

    // TODO: should we really be tweaking the buffering parameters?
    props.BufferSize = 1024;    // in KB
    props.MinimumBuffers = std::thread::hardware_concurrency() * 4;
    props.MaximumBuffers = std::thread::hardware_concurrency() * 6;

    ULONG status = StartSession( session );
    if( status != ERROR_SUCCESS )
        return {};

    return session;
}

static Session StartUserSession( const CHAR* name )
{
    Session session = {};

    size_t maxlen = sizeof( session.name ) - 1;
    strncpy( session.name, name, maxlen );
    session.name[maxlen] = '\0';

    auto& props = session.properties;
    props.LoggerNameOffset = offsetof( Session, name );
    props.Wnode.BufferSize = sizeof( Session );
    props.Wnode.Guid = NullGuid;
#ifdef TRACY_TIMER_QPC
    props.Wnode.ClientContext = 1;  // 1: QueryPerformanceCounter
#else
    props.Wnode.ClientContext = 3;  // 3: CPU Ticks (e.g., rdtsc)
#endif
    //props.Wnode.Flags = WNODE_FLAG_TRACED_GUID; // unnecessary for user sessions, apparently
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;

    ULONG status = StartSession( session );
    if( status != ERROR_SUCCESS )
        return {};

    return session;
}

bool IsSingletonKernelLoggerSession( Session& session )
{
    bool check = true;
    check &= ( session.handle == 0xFFFF );
    check &= ( strncmp( session.name, KERNEL_LOGGER_NAMEA, sizeof( session.name ) ) == 0 );
    return check;
}

static ULONG UpdateSessionEnableFlags( Session& session, ULONGLONG EnableFlags )
{
    // Use a copy of the session properties, because ControlTrace(UPDATE) will modify
    // LogFileNameOffset and "pad" the rest with zeros, overwriting the session.handle!
    Session temp = session;
    temp.properties.EnableFlags = EnableFlags;
    ULONG status = ControlTraceA( temp.handle, temp.name, &temp.properties, EVENT_TRACE_CONTROL_UPDATE );
    if( status != ERROR_SUCCESS )
        return ETWError( status );
    session.properties.EnableFlags = EnableFlags;
    return status;
}

static ULONG EnableProcessAndThreadMonitoring( Session& session )
{
    if( IsSingletonKernelLoggerSession( session ) )
    {
        ULONGLONG EnableFlags = session.properties.EnableFlags;
        EnableFlags |= EVENT_TRACE_FLAG_THREAD;
        ULONG status = UpdateSessionEnableFlags( session, EnableFlags );
        return status;
    }

    ULONGLONG MatchAnyKeyword = SYSTEM_PROCESS_KW_THREAD;   // ThreadStart and ThreadDCStart events
    ULONG status = EnableProvider( session, SystemProcessProviderGuid,
                                   EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, MatchAnyKeyword );
    return status;
}

static ULONG EnableCPUProfiling( Session& session, int microseconds = 125 /* 8KHz = 125us */ )
{
    if( !IsOS64Bit() )
        return 0 /* ERROR_SUCCESS */;   // TODO: fabricate SetLastError(ERROR_NOT_SUPPORTED) instead?

    // CPU Profiling requires special privileges on top of admin privileges
    DWORD access = ElevatePrivilege( SE_SYSTEM_PROFILE_NAME );
    if( access != ERROR_SUCCESS )
        return access;

    if( IsSingletonKernelLoggerSession( session ) )
    {
        ULONGLONG EnableFlags = session.properties.EnableFlags;
        EnableFlags |= EVENT_TRACE_FLAG_PROFILE;
        ULONG status = UpdateSessionEnableFlags( session, EnableFlags );
        if( status != ERROR_SUCCESS )
            return status;
    }
    else
    {
        CheckProviderSessions( SystemProfileProviderGuid, 0 );
        ULONG status = EnableProvider( session, SystemProfileProviderGuid );
        if( status != ERROR_SUCCESS )
            return status;
    }

    ULONG status = SetCPUProfilingInterval( microseconds );
    if( status != ERROR_SUCCESS )
        return status;

    status = EnableStackWalk( session, PerfInfoGuid, SampledProfile::Opcode );
    return status;
}

static ULONG EnableContextSwitchMonitoring( Session& session )
{
    if( IsSingletonKernelLoggerSession( session ) )
    {
        ULONGLONG EnableFlags = session.properties.EnableFlags;
        EnableFlags |= EVENT_TRACE_FLAG_CSWITCH;
        EnableFlags |= EVENT_TRACE_FLAG_DISPATCHER;
        ULONG status = UpdateSessionEnableFlags( session, EnableFlags );
        if( status != ERROR_SUCCESS )
            return status;
    }
    else
    {
        ULONGLONG MatchAnyKeyword = 0;
        MatchAnyKeyword |= SYSTEM_SCHEDULER_KW_CONTEXT_SWITCH;  // CSwitch events
        MatchAnyKeyword |= SYSTEM_SCHEDULER_KW_DISPATCHER;      // ReadyThread events
        CheckProviderSessions( SystemSchedulerProviderGuid, MatchAnyKeyword );
        ULONG status = EnableProvider( session, SystemSchedulerProviderGuid,
                                       EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, MatchAnyKeyword );
        if( status != ERROR_SUCCESS )
            return status;
    }

    ULONG status = EnableStackWalk( session, ThreadGuid, CSwitch::Opcode );
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
    // DxgKrnlPresent bit was added in Win11, but we do not want to break Win10, so do not put it in MatchAllKeyword
    ULONGLONG MatchAnyKeyword = Keyword::MSFTReserved62 /*| Keyword::DxgKrnlPresent*/ | Keyword::DxgKrnlBase;
    ULONGLONG MatchAllKeyword = MatchAnyKeyword;

    EVENT_FILTER_EVENT_ID fe = {};
    fe.FilterIn = TRUE;
    fe.Count = 1;
    fe.Events[0] = VSyncDPC::EventId;
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

    CheckProviderSessions( DxgKrnlGuid, MatchAnyKeyword );
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
    if( ( status != ERROR_SUCCESS ) && ( status != ERROR_CTX_CLOSE_PENDING ) )
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

}
}
