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

void WINAPI EventRecordCallback( PEVENT_RECORD record )
{
#ifdef TRACY_ON_DEMAND
    if( !GetProfiler().IsConnected() ) return;
#endif

    const auto& hdr = record->EventHeader;
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
    s_prop->EnableFlags = EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_DISPATCHER | EVENT_TRACE_FLAG_THREAD;
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
    SetThreadName( "Tracy SysTrace" );
    ProcessTrace( &s_traceHandle2, 1, 0, 0 );
    ControlTrace( 0, KERNEL_LOGGER_NAME, s_prop, EVENT_TRACE_CONTROL_STOP );
    tracy_free( s_prop );
}

#ifdef __CYGWIN__
extern "C" typedef DWORD (WINAPI *t_GetProcessIdOfThread)( HANDLE );
extern "C" typedef DWORD (WINAPI *t_GetProcessImageFileNameA)( HANDLE, LPSTR, DWORD );
#  ifdef UNICODE
t_GetProcessIdOfThread GetProcessIdOfThread = (t_GetProcessIdOfThread)GetProcAddress( GetModuleHandle( L"kernel32.dll" ), "GetProcessIdOfThread" );
t_GetProcessImageFileNameA GetProcessImageFileNameA = (t_GetProcessImageFileNameA)GetProcAddress( GetModuleHandle( L"kernel32.dll" ), "K32GetProcessImageFileNameA" );
#  else
t_GetProcessIdOfThread GetProcessIdOfThread = (t_GetProcessIdOfThread)GetProcAddress( GetModuleHandle( "kernel32.dll" ), "GetProcessIdOfThread" );
t_GetProcessImageFileNameA GetProcessImageFileNameA = (t_GetProcessImageFileNameA)GetProcAddress( GetModuleHandle( "kernel32.dll" ), "K32GetProcessImageFileNameA" );
#  endif
#endif

extern "C" typedef NTSTATUS (WINAPI *t_NtQueryInformationThread)( HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG );
extern "C" typedef BOOL (WINAPI *t_EnumProcessModules)( HANDLE, HMODULE*, DWORD, LPDWORD );
extern "C" typedef BOOL (WINAPI *t_GetModuleInformation)( HANDLE, HMODULE, LPMODULEINFO, DWORD );
extern "C" typedef DWORD (WINAPI *t_GetModuleBaseNameA)( HANDLE, HMODULE, LPSTR, DWORD );
#ifdef UNICODE
t_NtQueryInformationThread NtQueryInformationThread = (t_NtQueryInformationThread)GetProcAddress( GetModuleHandle( L"ntdll.dll" ), "NtQueryInformationThread" );
t_EnumProcessModules _EnumProcessModules = (t_EnumProcessModules)GetProcAddress( GetModuleHandle( L"kernel32.dll" ), "K32EnumProcessModules" );
t_GetModuleInformation _GetModuleInformation = (t_GetModuleInformation)GetProcAddress( GetModuleHandle( L"kernel32.dll" ), "K32GetModuleInformation" );
t_GetModuleBaseNameA _GetModuleBaseNameA = (t_GetModuleBaseNameA)GetProcAddress( GetModuleHandle( L"kernel32.dll" ), "K32GetModuleBaseNameA" );
#else
t_NtQueryInformationThread NtQueryInformationThread = (t_NtQueryInformationThread)GetProcAddress( GetModuleHandle( "ntdll.dll" ), "NtQueryInformationThread" );
t_EnumProcessModules _EnumProcessModules = (t_EnumProcessModules)GetProcAddress( GetModuleHandle( "kernel32.dll" ), "K32EnumProcessModules" );
t_GetModuleInformation _GetModuleInformation = (t_GetModuleInformation)GetProcAddress( GetModuleHandle( "kernel32.dll" ), "K32GetModuleInformation" );
t_GetModuleBaseNameA _GetModuleBaseNameA = (t_GetModuleBaseNameA)GetProcAddress( GetModuleHandle( "kernel32.dll" ), "K32GetModuleBaseNameA" );
#endif


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
                                    char buf[1024];
                                    if( _GetModuleBaseNameA( phnd, modules[i], buf, 1024 ) != 0 )
                                    {
                                        GetProfiler().SendString( thread, buf, QueueType::ExternalThreadName );
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
            GetProfiler().SendString( thread, "???", QueueType::ExternalThreadName );
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
                GetProfiler().SendString( thread, "System", QueueType::ExternalName );
                return;
            }
            else
            {
                const auto phnd = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
                if( phnd != INVALID_HANDLE_VALUE )
                {
                    char buf[1024];
                    const auto sz = GetProcessImageFileNameA( phnd, buf, 1024 );
                    CloseHandle( phnd );
                    if( sz != 0 )
                    {
                        auto ptr = buf + sz - 1;
                        while( ptr > buf && *ptr != '\\' ) ptr--;
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
        GetProfiler().SendString( thread, "???", QueueType::ExternalThreadName );
    }
    GetProfiler().SendString( thread, "???", QueueType::ExternalName );
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

#    include "TracyProfiler.hpp"

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

#ifdef __ANDROID__
static bool TraceWrite( const char* path, size_t psz, const char* val, size_t vsz )
{
    char tmp[256];
    sprintf( tmp, "su -c 'echo \"%s\" > %s%s'", val, BasePath, path );
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
                execlp( "su", "su", "-c", "cat > /data/tracy_systrace", (char*)nullptr );
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

            system( "su -c 'chmod 700 /data/tracy_systrace'" );
        }
    }
}
#endif

bool SysTraceStart()
{
    if( !TraceWrite( TracingOn, sizeof( TracingOn ), "0", 2 ) ) return false;
    if( !TraceWrite( CurrentTracer, sizeof( CurrentTracer ), "nop", 4 ) ) return false;
    TraceWrite( TraceOptions, sizeof( TraceOptions ), "norecord-cmd", 13 );
    TraceWrite( TraceOptions, sizeof( TraceOptions ), "norecord-tgid", 14 );
    TraceWrite( TraceOptions, sizeof( TraceOptions ), "noirq-info", 11 );
#if defined TRACY_HW_TIMER && ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
    if( !TraceWrite( TraceClock, sizeof( TraceClock ), "x86-tsc", 8 ) ) return false;
#elif __ARM_ARCH >= 6
    if( !TraceWrite( TraceClock, sizeof( TraceClock ), "mono_raw", 9 ) ) return false;
#endif
    if( !TraceWrite( SchedSwitch, sizeof( SchedSwitch ), "1", 2 ) ) return false;
    if( !TraceWrite( SchedWakeup, sizeof( SchedWakeup ), "1", 2 ) ) return false;
    if( !TraceWrite( BufferSizeKb, sizeof( BufferSizeKb ), "512", 4 ) ) return false;

#if defined __ANDROID__ && ( defined __aarch64__ || defined __ARM_ARCH )
    SysTraceInjectPayload();
#endif

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
    line += 24;
    const auto cpu = (uint8_t)ReadNumber( line );

    line++;      // ']'
    while( *line == ' ' ) line++;

#if defined TRACY_HW_TIMER && ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
    const auto time = ReadNumber( line );
#elif __ARM_ARCH >= 6
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
            auto next = line;
            while( next < end && *next != '\n' ) next++;
            next++;
            if( next >= end )
            {
                const auto lsz = end - line;
                memmove( buf, line, lsz );
                line = buf + lsz;
                break;
            }

            HandleTraceLine( line );
            line = next;
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
    SetThreadName( "Tracy SysTrace" );
    int pipefd[2];
    if( pipe( pipefd ) == 0 )
    {
        const auto pid = fork();
        if( pid == 0 )
        {
            // child
            close( pipefd[0] );
            dup2( pipefd[1], STDERR_FILENO );
            if( dup2( pipefd[1], STDOUT_FILENO ) >= 0 )
            {
                close( pipefd[1] );
#if defined __ANDROID__ && ( defined __aarch64__ || defined __ARM_ARCH )
                execlp( "su", "su", "-c", "/data/tracy_systrace", (char*)nullptr );
#endif
                execlp( "su", "su", "-c", "cat /sys/kernel/debug/tracing/trace_pipe", (char*)nullptr );
                exit( 1 );
            }
        }
        else if( pid > 0 )
        {
            // parent
            close( pipefd[1] );
            ProcessTraceLines( pipefd[0] );
            close( pipefd[0] );
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
        while( poll( &pfd, 1, 0 ) <= 0 ) std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );

        const auto rd = read( fd, buf, 64*1024 );
        if( rd <= 0 ) break;

#ifdef TRACY_ON_DEMAND
        if( !GetProfiler().IsConnected() ) continue;
#endif

        auto line = buf;
        const auto end = buf + rd;
        for(;;)
        {
            auto next = line;
            while( next < end && *next != '\n' ) next++;
            if( next == end ) break;
            assert( *next == '\n' );
            next++;

            HandleTraceLine( line );
            line = next;
        }
    }

    tracy_free( buf );
}

void SysTraceWorker( void* ptr )
{
    SetThreadName( "Tracy SysTrace" );
    char tmp[256];
    memcpy( tmp, BasePath, sizeof( BasePath ) - 1 );
    memcpy( tmp + sizeof( BasePath ) - 1, TracePipe, sizeof( TracePipe ) );

    int fd = open( tmp, O_RDONLY );
    if( fd < 0 ) return;
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
        GetProfiler().SendString( thread, "???", QueueType::ExternalThreadName );
    }

    sprintf( fn, "/proc/%" PRIu64 "/status", thread );
    f = fopen( fn, "rb" );
    if( f )
    {
        int pid = -1;
        size_t lsz = 1024;
        auto line = (char*)malloc( lsz );
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
        free( line );
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
    GetProfiler().SendString( thread, "???", QueueType::ExternalName );
}

}

#  endif

#endif
