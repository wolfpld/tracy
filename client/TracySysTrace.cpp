#include "TracySysTrace.hpp"

#ifdef TRACY_HAS_SYSTEM_TRACING

#  if defined _WIN32 || defined __CYGWIN__

#    define INITGUID
#    include <assert.h>
#    include <stdint.h>
#    include <string.h>
#    include <windows.h>
#    include <evntrace.h>
#    include <evntcons.h>

#    include "../common/TracyAlloc.hpp"
#    include "TracyProfiler.hpp"

namespace tracy
{

TRACEHANDLE s_traceHandle;
TRACEHANDLE s_traceHandle2;

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
    auto prop = (EVENT_TRACE_PROPERTIES*)tracy_malloc( psz );
    memset( prop, 0, sizeof( EVENT_TRACE_PROPERTIES ) );
    prop->EnableFlags = EVENT_TRACE_FLAG_CSWITCH;
    prop->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    prop->Wnode.BufferSize = psz;
    prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    prop->Wnode.ClientContext = 3;
    prop->Wnode.Guid = SystemTraceControlGuid;
    prop->LoggerNameOffset = sizeof( EVENT_TRACE_PROPERTIES );
    memcpy( ((char*)prop) + sizeof( EVENT_TRACE_PROPERTIES ), KERNEL_LOGGER_NAME, sizeof( KERNEL_LOGGER_NAME ) );

    auto backup = tracy_malloc( psz );
    memcpy( backup, prop, psz );

    const auto controlStatus = ControlTrace( 0, KERNEL_LOGGER_NAME, prop, EVENT_TRACE_CONTROL_STOP );
    if( controlStatus != ERROR_SUCCESS && controlStatus != ERROR_WMI_INSTANCE_NOT_FOUND )
    {
        tracy_free( prop );
        return false;
    }

    memcpy( prop, backup, psz );
    tracy_free( backup );

    const auto startStatus = StartTrace( &s_traceHandle, KERNEL_LOGGER_NAME, prop );
    tracy_free( prop );
    if( startStatus != ERROR_SUCCESS ) return false;

    EVENT_TRACE_LOGFILE log = {};
    log.LoggerName = KERNEL_LOGGER_NAME;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.EventRecordCallback = EventRecordCallback;

    s_traceHandle2 = OpenTrace( &log );
    if( s_traceHandle2 == (TRACEHANDLE)INVALID_HANDLE_VALUE )
    {
        CloseTrace( s_traceHandle );
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
    ProcessTrace( &s_traceHandle2, 1, 0, 0 );
}

}

#  endif

#endif
