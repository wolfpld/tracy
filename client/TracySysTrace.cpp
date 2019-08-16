#include "TracySysTrace.hpp"

#ifdef TRACY_HAS_SYSTEM_TRACING

#  if defined _WIN32 || defined __CYGWIN__

#    define INITGUID
#    include <assert.h>
#    include <string.h>
#    include <windows.h>
#    include <evntrace.h>
#    include <evntcons.h>
#    include <psapi.h>

#    include "../common/TracyAlloc.hpp"
#    include "../common/TracySystem.hpp"
#    include "TracyProfiler.hpp"

namespace tracy
{

TRACEHANDLE s_traceHandle;
TRACEHANDLE s_traceHandle2;
EVENT_TRACE_PROPERTIES* s_prop;

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

void EventRecordCallback( PEVENT_RECORD record )
{
#ifdef TRACY_ON_DEMAND
    if( !GetProfiler().IsConnected() ) return;
#endif

    const auto& hdr = record->EventHeader;
    if( hdr.EventDescriptor.Opcode != 36 ) return;

    const auto cswitch = (const CSwitch*)record->UserData;

    static_assert( sizeof( record->BufferContext.ProcessorNumber ) == sizeof( uint8_t ), "Bad data size" );
    static_assert( sizeof( cswitch->oldThreadId ) == sizeof( uint32_t ), "Bad data size" );
    static_assert( sizeof( cswitch->newThreadId ) == sizeof( uint32_t ), "Bad data size" );
    static_assert( sizeof( hdr.TimeStamp.QuadPart ) == sizeof( int64_t ), "Bad data size" );
    static_assert( sizeof( cswitch->oldThreadWaitReason ) == sizeof( uint8_t ), "Bad data size" );
    static_assert( sizeof( cswitch->oldThreadState ) == sizeof( uint8_t ), "Bad data size" );

    Magic magic;
    auto token = GetToken();
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin( magic );
    MemWrite( &item->hdr.type, QueueType::ContextSwitch );
    MemWrite( &item->contextSwitch.time, hdr.TimeStamp.QuadPart );
    memcpy( &item->contextSwitch.oldThread, &cswitch->oldThreadId, sizeof( cswitch->oldThreadId ) );
    memcpy( &item->contextSwitch.newThread, &cswitch->newThreadId, sizeof( cswitch->newThreadId ) );
    memset( ((char*)&item->contextSwitch.oldThread)+4, 0, 4 );
    memset( ((char*)&item->contextSwitch.newThread)+4, 0, 4 );
    MemWrite( &item->contextSwitch.cpu, record->BufferContext.ProcessorNumber );
    MemWrite( &item->contextSwitch.reason, cswitch->oldThreadWaitReason );
    MemWrite( &item->contextSwitch.state, cswitch->oldThreadState );
    tail.store( magic + 1, std::memory_order_release );
}

bool SysTraceStart()
{
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

    const auto psz = sizeof( EVENT_TRACE_PROPERTIES ) + sizeof( KERNEL_LOGGER_NAME );
    s_prop = (EVENT_TRACE_PROPERTIES*)tracy_malloc( psz );
    memset( s_prop, 0, sizeof( EVENT_TRACE_PROPERTIES ) );
    s_prop->EnableFlags = EVENT_TRACE_FLAG_CSWITCH;
    s_prop->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    s_prop->Wnode.BufferSize = psz;
    s_prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    s_prop->Wnode.ClientContext = 3;
    s_prop->Wnode.Guid = SystemTraceControlGuid;
    s_prop->LoggerNameOffset = sizeof( EVENT_TRACE_PROPERTIES );
    memcpy( ((char*)s_prop) + sizeof( EVENT_TRACE_PROPERTIES ), KERNEL_LOGGER_NAME, sizeof( KERNEL_LOGGER_NAME ) );

    auto backup = tracy_malloc( psz );
    memcpy( backup, s_prop, psz );

    const auto controlStatus = ControlTrace( 0, KERNEL_LOGGER_NAME, s_prop, EVENT_TRACE_CONTROL_STOP );
    if( controlStatus != ERROR_SUCCESS && controlStatus != ERROR_WMI_INSTANCE_NOT_FOUND )
    {
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

    return true;
}

void SysTraceStop()
{
    CloseTrace( s_traceHandle2 );
    CloseTrace( s_traceHandle );
}

void SysTraceWorker( void* ptr )
{
    SetThreadName( "Tracy Profiler system trace" );
    ProcessTrace( &s_traceHandle2, 1, 0, 0 );
    ControlTrace( 0, KERNEL_LOGGER_NAME, s_prop, EVENT_TRACE_CONTROL_STOP );
    tracy_free( s_prop );
}

void SysTraceSendExternalName( uint64_t thread )
{
    bool threadSent = false;
    const auto hnd = OpenThread( THREAD_QUERY_LIMITED_INFORMATION, FALSE, thread );
    if( hnd != INVALID_HANDLE_VALUE )
    {
#if defined NTDDI_WIN10_RS2 && NTDDI_VERSION >= NTDDI_WIN10_RS2
        PWSTR tmp;
        GetThreadDescription( hnd, &tmp );
        char buf[256];
        if( tmp )
        {
            auto ret = wcstombs( buf, tmp, 256 );
            if( ret != 0 )
            {
                GetProfiler().SendString( thread, buf, QueueType::ExternalThreadName );
                threadSent = true;
            }
        }
#endif
        const auto pid = GetProcessIdOfThread( hnd );
        CloseHandle( hnd );
        if( pid != 0 )
        {
            const auto phnd = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
            if( phnd != INVALID_HANDLE_VALUE )
            {
                char buf[1024];
                const auto sz = GetProcessImageFileNameA( phnd, buf, 1024 );
                CloseHandle( phnd );
                if( sz != 0 )
                {
                    if( !threadSent )
                    {
                        GetProfiler().SendString( thread, "???", QueueType::ExternalThreadName );
                    }
                    auto ptr = buf + sz - 1;
                    while( ptr > buf && *ptr != '\\' ) ptr--;
                    if( *ptr == '\\' ) ptr++;
                    GetProfiler().SendString( thread, ptr, QueueType::ExternalName );
                    return;
                }
            }
        }
    }

    GetProfiler().SendString( thread, "???", QueueType::ExternalThreadName );
    GetProfiler().SendString( thread, "???", QueueType::ExternalName );
}

}

#  elif defined __linux__

#    include <sys/types.h>
#    include <sys/stat.h>
#    include <fcntl.h>
#    include <stdio.h>
#    include <string.h>
#    include <unistd.h>

#    include "TracyProfiler.hpp"

namespace tracy
{

static const char BasePath[] = "/sys/kernel/debug/tracing/";
static const char TracingOn[] = "tracing_on";
static const char CurrentTracer[] = "current_tracer";
static const char TraceOptions[] = "trace_options";
static const char TraceClock[] = "trace_clock";
static const char SchedSwitch[] = "events/sched/sched_switch/enable";
static const char TracePipe[] = "trace_pipe";

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

bool SysTraceStart()
{
    if( !TraceWrite( TracingOn, sizeof( TracingOn ), "0", 2 ) ) return false;
    if( !TraceWrite( CurrentTracer, sizeof( CurrentTracer ), "nop", 4 ) ) return false;
    if( !TraceWrite( TraceOptions, sizeof( TraceOptions ), "norecord-cmd", 13 ) ) return false;
    if( !TraceWrite( TraceOptions, sizeof( TraceOptions ), "norecord-tgid", 14 ) ) return false;
    if( !TraceWrite( TraceOptions, sizeof( TraceOptions ), "noirq-info", 11 ) ) return false;
#if defined TRACY_HW_TIMER && ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
    if( !TraceWrite( TraceClock, sizeof( TraceClock ), "x86-tsc", 8 ) ) return false;
#elif __ARM_ARCH >= 6
    if( !TraceWrite( TraceClock, sizeof( TraceClock ), "mono_raw", 8 ) ) return false;
#endif
    if( !TraceWrite( SchedSwitch, sizeof( SchedSwitch ), "1", 2 ) ) return false;
    if( !TraceWrite( TracingOn, sizeof( TracingOn ), "1", 2 ) ) return false;

    return true;
}

void SysTraceStop()
{
    TraceWrite( TracingOn, sizeof( TracingOn ), "0", 2 );
}

static uint64_t ReadNumber( const char*& ptr )
{
    uint64_t val = 0;
    for(;;)
    {
        if( *ptr >= '0' && *ptr <= '9' )
        {
            val = val * 10 + ( *ptr - '0' );
            ptr++;
        }
        else
        {
            return val;
        }
    }
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

void SysTraceWorker( void* ptr )
{
    char tmp[256];
    memcpy( tmp, BasePath, sizeof( BasePath ) - 1 );
    memcpy( tmp + sizeof( BasePath ) - 1, TracePipe, sizeof( TracePipe ) );

    FILE* f = fopen( tmp, "rb" );
    if( !f ) return;

    size_t lsz = 1024;
    auto line = (char*)malloc( lsz );

    for(;;)
    {
        auto rd = getline( &line, &lsz, f );
        if( rd < 0 ) break;

#ifdef TRACY_ON_DEMAND
        if( !GetProfiler().IsConnected() ) continue;
#endif

        const char* ptr = line + 24;
        const auto cpu = (uint8_t)ReadNumber( ptr );

        ptr++;      // ']'
        while( *ptr == ' ' ) ptr++;

#if defined TRACY_HW_TIMER && ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
        const auto time = ReadNumber( ptr );
#elif __ARM_ARCH >= 6
        const auto ts = ReadNumber( ptr );
        ptr++;      // '.'
        const auto tus = ReadNumber( ptr );
        const auto time = ts * 1000000000ll + tus * 1000ll;
#endif

        ptr += 2;   // ': '
        if( memcmp( ptr, "sched_switch", 12 ) != 0 ) continue;
        ptr += 14;

        while( memcmp( ptr, "prev_pid", 8 ) != 0 ) ptr++;
        ptr += 9;

        const auto oldPid = ReadNumber( ptr );
        ptr++;

        while( memcmp( ptr, "prev_state", 10 ) != 0 ) ptr++;
        ptr += 11;

        const auto oldState = (uint8_t)ReadState( *ptr );
        ptr += 5;

        while( memcmp( ptr, "next_pid", 8 ) != 0 ) ptr++;
        ptr += 9;

        const auto newPid = ReadNumber( ptr );

        uint8_t reason = 100;

        Magic magic;
        auto token = GetToken();
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin( magic );
        MemWrite( &item->hdr.type, QueueType::ContextSwitch );
        MemWrite( &item->contextSwitch.time, time );
        MemWrite( &item->contextSwitch.oldThread, oldPid );
        MemWrite( &item->contextSwitch.newThread, newPid );
        MemWrite( &item->contextSwitch.cpu, cpu );
        MemWrite( &item->contextSwitch.reason, reason );
        MemWrite( &item->contextSwitch.state, oldState );
        tail.store( magic + 1, std::memory_order_release );
    }

    free( line );
    fclose( f );
}

void SysTraceSendExternalName( uint64_t thread )
{
    // TODO
    GetProfiler().SendString( thread, "???", QueueType::ExternalThreadName );
    GetProfiler().SendString( thread, "???", QueueType::ExternalName );
}

}

#  endif

#endif
