#ifdef TRACY_ENABLE

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <windows.h>
#  include <tlhelp32.h>
#  include <inttypes.h>
#  include <intrin.h>
#else
#  include <sys/time.h>
#  include <sys/param.h>
#endif

#ifdef __CYGWIN__
#  include <windows.h>
#  include <unistd.h>
#  include <tlhelp32.h>
#endif

#ifdef _GNU_SOURCE
#  include <errno.h>
#endif

#ifdef __linux__
#  include <dirent.h>
#  include <signal.h>
#  include <pthread.h>
#  include <sys/types.h>
#  include <sys/syscall.h>
#endif

#if defined __APPLE__ || defined BSD
#  include <sys/types.h>
#  include <sys/sysctl.h>
#endif

#if defined __APPLE__
#  include "TargetConditionals.h"
#endif

#ifdef __ANDROID__
#  include <sys/mman.h>
#  include <stdio.h>
#  include <stdint.h>
#  include <algorithm>
#  include <vector>
#endif

#include <algorithm>
#include <assert.h>
#include <atomic>
#include <chrono>
#include <limits>
#include <new>
#include <stdlib.h>
#include <string.h>
#include <thread>

#include "../common/TracyAlign.hpp"
#include "../common/TracySocket.hpp"
#include "../common/TracySystem.hpp"
#include "../common/tracy_lz4.hpp"
#include "tracy_rpmalloc.hpp"
#include "TracyCallstack.hpp"
#include "TracyDxt1.hpp"
#include "TracyScoped.hpp"
#include "TracyProfiler.hpp"
#include "TracyThread.hpp"
#include "TracyArmCpuTable.hpp"
#include "TracySysTrace.hpp"
#include "../TracyC.h"

#ifdef TRACY_PORT
#  ifndef TRACY_DATA_PORT
#    define TRACY_DATA_PORT TRACY_PORT
#  endif
#  ifndef TRACY_BROADCAST_PORT
#    define TRACY_BROADCAST_PORT TRACY_PORT
#  endif
#endif

#ifdef __APPLE__
#  define TRACY_DELAYED_INIT
#else
#  ifdef __GNUC__
#    define init_order( val ) __attribute__ ((init_priority(val)))
#  else
#    define init_order(x)
#  endif
#endif

#if defined _WIN32 || defined __CYGWIN__
#  include <lmcons.h>
extern "C" typedef LONG (WINAPI *t_RtlGetVersion)( PRTL_OSVERSIONINFOW );
extern "C" typedef BOOL (WINAPI *t_GetLogicalProcessorInformationEx)( LOGICAL_PROCESSOR_RELATIONSHIP, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, PDWORD );
#else
#  include <unistd.h>
#  include <limits.h>
#endif
#if defined __linux__
#  include <sys/sysinfo.h>
#  include <sys/utsname.h>
#endif

#if !defined _WIN32 && !defined __CYGWIN__ && ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 )
#  include <cpuid.h>
#endif

#if !( ( ( defined _WIN32 || defined __CYGWIN__ ) && _WIN32_WINNT >= _WIN32_WINNT_VISTA ) || defined __linux__ )
#  include <mutex>
#endif

namespace tracy
{

namespace
{
#  if ( defined _WIN32 || defined __CYGWIN__ ) && _WIN32_WINNT >= _WIN32_WINNT_VISTA
    BOOL CALLBACK InitOnceCallback( PINIT_ONCE /*initOnce*/, PVOID /*Parameter*/, PVOID* /*Context*/)
    {
        rpmalloc_initialize();
        return TRUE;
    }
    INIT_ONCE InitOnce = INIT_ONCE_STATIC_INIT;
#  elif defined __linux__
    void InitOnceCallback()
    {
        rpmalloc_initialize();
    }
    pthread_once_t once_control = PTHREAD_ONCE_INIT;
#  else
    void InitOnceCallback()
    {
        rpmalloc_initialize();
    }
    std::once_flag once_flag;
#  endif
}

struct RPMallocInit
{
    RPMallocInit()
    {
#  if ( defined _WIN32 || defined __CYGWIN__ ) && _WIN32_WINNT >= _WIN32_WINNT_VISTA
        InitOnceExecuteOnce( &InitOnce, InitOnceCallback, nullptr, nullptr );
#  elif defined __linux__
        pthread_once( &once_control, InitOnceCallback );
#  else
        std::call_once( once_flag, InitOnceCallback );
#  endif
        rpmalloc_thread_initialize();
    }
};

#ifndef TRACY_DELAYED_INIT

struct InitTimeWrapper
{
    int64_t val;
};

struct ProducerWrapper
{
    tracy::moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* ptr;
};

struct ThreadHandleWrapper
{
    uint64_t val;
};
#endif


#if defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64
static inline void CpuId( uint32_t* regs, uint32_t leaf )
{
    memset(regs, 0, sizeof(uint32_t) * 4);
#if defined _WIN32 || defined __CYGWIN__
    __cpuidex( (int*)regs, leaf, 0 );
#else
    __get_cpuid( leaf, regs, regs+1, regs+2, regs+3 );
#endif
}

static void InitFailure( const char* msg )
{
#if defined _WIN32 || defined __CYGWIN__
    bool hasConsole = false;
    bool reopen = false;
    const auto attached = AttachConsole( ATTACH_PARENT_PROCESS );
    if( attached )
    {
        hasConsole = true;
        reopen = true;
    }
    else
    {
        const auto err = GetLastError();
        if( err == ERROR_ACCESS_DENIED )
        {
            hasConsole = true;
        }
    }
    if( hasConsole )
    {
        fprintf( stderr, "Tracy Profiler initialization failure: %s\n", msg );
        if( reopen )
        {
            freopen( "CONOUT$", "w", stderr );
            fprintf( stderr, "Tracy Profiler initialization failure: %s\n", msg );
        }
    }
    else
    {
        MessageBoxA( nullptr, msg, "Tracy Profiler initialization failure", MB_ICONSTOP );
    }
#else
    fprintf( stderr, "Tracy Profiler initialization failure: %s\n", msg );
#endif
    exit( 0 );
}

static int64_t SetupHwTimer()
{
#if !defined TRACY_TIMER_QPC && !defined TRACY_TIMER_FALLBACK
    uint32_t regs[4];
    CpuId( regs, 1 );
    if( !( regs[3] & ( 1 << 4 ) ) ) InitFailure( "CPU doesn't support RDTSC instruction." );
    CpuId( regs, 0x80000007 );
    if( !( regs[3] & ( 1 << 8 ) ) )
    {
        const char* noCheck = getenv( "TRACY_NO_INVARIANT_CHECK" );
        if( !noCheck || noCheck[0] != '1' )
        {
#if defined _WIN32 || defined __CYGWIN__
            InitFailure( "CPU doesn't support invariant TSC.\nDefine TRACY_NO_INVARIANT_CHECK=1 to ignore this error, *if you know what you are doing*.\nAlternatively you may rebuild the application with the TRACY_TIMER_QPC or TRACY_TIMER_FALLBACK define to use lower resolution timer." );
#else
            InitFailure( "CPU doesn't support invariant TSC.\nDefine TRACY_NO_INVARIANT_CHECK=1 to ignore this error, *if you know what you are doing*.\nAlternatively you may rebuild the application with the TRACY_TIMER_FALLBACK define to use lower resolution timer." );
#endif
        }
    }
#endif

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
    const char* processName = "unknown";
#ifdef _WIN32
    static char buf[_MAX_PATH];
    GetModuleFileNameA( nullptr, buf, _MAX_PATH );
    const char* ptr = buf;
    while( *ptr != '\0' ) ptr++;
    while( ptr > buf && *ptr != '\\' && *ptr != '/' ) ptr--;
    if( ptr > buf ) ptr++;
    processName = ptr;
#elif defined __ANDROID__
#  if __ANDROID_API__ >= 21
    auto buf = getprogname();
    if( buf ) processName = buf;
#  endif
#elif defined _GNU_SOURCE || defined __CYGWIN__
    processName = program_invocation_short_name;
#elif defined __APPLE__ || defined BSD
    auto buf = getprogname();
    if( buf ) processName = buf;
#endif
    return processName;
}

#if defined __linux__ && defined __ARM_ARCH
static uint32_t GetHex( char*& ptr, int skip )
{
    uint32_t ret;
    ptr += skip;
    char* end;
    if( ptr[0] == '0' && ptr[1] == 'x' )
    {
        ptr += 2;
        ret = strtol( ptr, &end, 16 );
    }
    else
    {
        ret = strtol( ptr, &end, 10 );
    }
    ptr = end;
    return ret;
}
#endif

static const char* GetHostInfo()
{
    static char buf[1024];
    auto ptr = buf;
#if defined _WIN32 || defined __CYGWIN__
    t_RtlGetVersion RtlGetVersion = (t_RtlGetVersion)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "RtlGetVersion" );
    if( !RtlGetVersion )
    {
#  ifdef __CYGWIN__
        ptr += sprintf( ptr, "OS: Windows (Cygwin)\n" );
#  elif defined __MINGW32__
        ptr += sprintf( ptr, "OS: Windows (MingW)\n" );
#  else
        ptr += sprintf( ptr, "OS: Windows\n" );
#  endif
    }
    else
    {
        RTL_OSVERSIONINFOW ver = { sizeof( RTL_OSVERSIONINFOW ) };
        RtlGetVersion( &ver );

#  ifdef __CYGWIN__
        ptr += sprintf( ptr, "OS: Windows %i.%i.%i (Cygwin)\n", ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber );
#  elif defined __MINGW32__
        ptr += sprintf( ptr, "OS: Windows %i.%i.%i (MingW)\n", (int)ver.dwMajorVersion, (int)ver.dwMinorVersion, (int)ver.dwBuildNumber );
#  else
        ptr += sprintf( ptr, "OS: Windows %i.%i.%i\n", ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber );
#  endif
    }
#elif defined __linux__
    struct utsname utsName;
    uname( &utsName );
#  if defined __ANDROID__
    ptr += sprintf( ptr, "OS: Linux %s (Android)\n", utsName.release );
#  else
    ptr += sprintf( ptr, "OS: Linux %s\n", utsName.release );
#  endif
#elif defined __APPLE__
#  if TARGET_OS_IPHONE == 1
    ptr += sprintf( ptr, "OS: Darwin (iOS)\n" );
#  elif TARGET_OS_MAC == 1
    ptr += sprintf( ptr, "OS: Darwin (OSX)\n" );
#  else
    ptr += sprintf( ptr, "OS: Darwin (unknown)\n" );
#  endif
#elif defined __DragonFly__
    ptr += sprintf( ptr, "OS: BSD (DragonFly)\n" );
#elif defined __FreeBSD__
    ptr += sprintf( ptr, "OS: BSD (FreeBSD)\n" );
#elif defined __NetBSD__
    ptr += sprintf( ptr, "OS: BSD (NetBSD)\n" );
#elif defined __OpenBSD__
    ptr += sprintf( ptr, "OS: BSD (OpenBSD)\n" );
#else
    ptr += sprintf( ptr, "OS: unknown\n" );
#endif

#if defined _MSC_VER
#  if defined __clang__
    ptr += sprintf( ptr, "Compiler: MSVC clang-cl %i.%i.%i\n", __clang_major__, __clang_minor__, __clang_patchlevel__ );
#  else
    ptr += sprintf( ptr, "Compiler: MSVC %i\n", _MSC_VER );
#  endif
#elif defined __clang__
    ptr += sprintf( ptr, "Compiler: clang %i.%i.%i\n", __clang_major__, __clang_minor__, __clang_patchlevel__ );
#elif defined __GNUC__
    ptr += sprintf( ptr, "Compiler: gcc %i.%i\n", __GNUC__, __GNUC_MINOR__ );
#else
    ptr += sprintf( ptr, "Compiler: unknown\n" );
#endif

#if defined _WIN32 || defined __CYGWIN__
#  ifndef __CYGWIN__
    InitWinSock();
#  endif
    char hostname[512];
    gethostname( hostname, 512 );

    DWORD userSz = UNLEN+1;
    char user[UNLEN+1];
    GetUserNameA( user, &userSz );

    ptr += sprintf( ptr, "User: %s@%s\n", user, hostname );
#else
    char hostname[_POSIX_HOST_NAME_MAX]{};
    char user[_POSIX_LOGIN_NAME_MAX]{};

    gethostname( hostname, _POSIX_HOST_NAME_MAX );
#  if defined __ANDROID__
    const auto login = getlogin();
    if( login )
    {
        strcpy( user, login );
    }
    else
    {
        memcpy( user, "(?)", 4 );
    }
#  else
    getlogin_r( user, _POSIX_LOGIN_NAME_MAX );
#  endif

    ptr += sprintf( ptr, "User: %s@%s\n", user, hostname );
#endif

#if defined __i386 || defined _M_IX86
    ptr += sprintf( ptr, "Arch: x86\n" );
#elif defined __x86_64__ || defined _M_X64
    ptr += sprintf( ptr, "Arch: x64\n" );
#elif defined __aarch64__
    ptr += sprintf( ptr, "Arch: ARM64\n" );
#elif defined __ARM_ARCH
    ptr += sprintf( ptr, "Arch: ARM\n" );
#else
    ptr += sprintf( ptr, "Arch: unknown\n" );
#endif

#if defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64
    uint32_t regs[4];
    char cpuModel[4*4*3];
    auto modelPtr = cpuModel;
    for( uint32_t i=0x80000002; i<0x80000005; ++i )
    {
        CpuId( regs, i );
        memcpy( modelPtr, regs, sizeof( regs ) ); modelPtr += sizeof( regs );
    }

    ptr += sprintf( ptr, "CPU: %s\n", cpuModel );
#elif defined __linux__ && defined __ARM_ARCH
    bool cpuFound = false;
    FILE* fcpuinfo = fopen( "/proc/cpuinfo", "rb" );
    if( fcpuinfo )
    {
        enum { BufSize = 4*1024 };
        char buf[BufSize];
        const auto sz = fread( buf, 1, BufSize, fcpuinfo );
        fclose( fcpuinfo );
        const auto end = buf + sz;
        auto cptr = buf;

        uint32_t impl = 0;
        uint32_t var = 0;
        uint32_t part = 0;
        uint32_t rev = 0;

        while( end - cptr > 20 )
        {
            while( end - cptr > 20 && memcmp( cptr, "CPU ", 4 ) != 0 )
            {
                cptr += 4;
                while( end - cptr > 20 && *cptr != '\n' ) cptr++;
                cptr++;
            }
            if( end - cptr <= 20 ) break;
            cptr += 4;
            if( memcmp( cptr, "implementer\t: ", 14 ) == 0 )
            {
                if( impl != 0 ) break;
                impl = GetHex( cptr, 14 );
            }
            else if( memcmp( cptr, "variant\t: ", 10 ) == 0 ) var = GetHex( cptr, 10 );
            else if( memcmp( cptr, "part\t: ", 7 ) == 0 ) part = GetHex( cptr, 7 );
            else if( memcmp( cptr, "revision\t: ", 11 ) == 0 ) rev = GetHex( cptr, 11 );
            while( *cptr != '\n' && *cptr != '\0' ) cptr++;
            cptr++;
        }

        if( impl != 0 || var != 0 || part != 0 || rev != 0 )
        {
            cpuFound = true;
            ptr += sprintf( ptr, "CPU: %s%s r%ip%i\n", DecodeArmImplementer( impl ), DecodeArmPart( impl, part ), var, rev );
        }
    }
    if( !cpuFound )
    {
        ptr += sprintf( ptr, "CPU: unknown\n" );
    }
#elif defined __APPLE__ && TARGET_OS_IPHONE == 1
    {
        size_t sz;
        sysctlbyname( "hw.machine", nullptr, &sz, nullptr, 0 );
        auto str = (char*)tracy_malloc( sz );
        sysctlbyname( "hw.machine", str, &sz, nullptr, 0 );
        ptr += sprintf( ptr, "Device: %s\n", DecodeIosDevice( str ) );
        tracy_free( str );
    }
#else
    ptr += sprintf( ptr, "CPU: unknown\n" );
#endif

    ptr += sprintf( ptr, "CPU cores: %i\n", std::thread::hardware_concurrency() );

#if defined _WIN32 || defined __CYGWIN__
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof( statex );
    GlobalMemoryStatusEx( &statex );
#  ifdef _MSC_VER
    ptr += sprintf( ptr, "RAM: %I64u MB\n", statex.ullTotalPhys / 1024 / 1024 );
#  else
    ptr += sprintf( ptr, "RAM: %llu MB\n", statex.ullTotalPhys / 1024 / 1024 );
#  endif
#elif defined __linux__
    struct sysinfo sysInfo;
    sysinfo( &sysInfo );
    ptr += sprintf( ptr, "RAM: %lu MB\n", sysInfo.totalram / 1024 / 1024 );
#elif defined __APPLE__
    size_t memSize;
    size_t sz = sizeof( memSize );
    sysctlbyname( "hw.memsize", &memSize, &sz, nullptr, 0 );
    ptr += sprintf( ptr, "RAM: %zu MB\n", memSize / 1024 / 1024 );
#elif defined BSD
    size_t memSize;
    size_t sz = sizeof( memSize );
    sysctlbyname( "hw.physmem", &memSize, &sz, nullptr, 0 );
    ptr += sprintf( ptr, "RAM: %zu MB\n", memSize / 1024 / 1024 );
#else
    ptr += sprintf( ptr, "RAM: unknown\n" );
#endif

    return buf;
}

static uint64_t GetPid()
{
#if defined _WIN32 || defined __CYGWIN__
    return uint64_t( GetCurrentProcessId() );
#else
    return uint64_t( getpid() );
#endif
}

static BroadcastMessage& GetBroadcastMessage( const char* procname, size_t pnsz, int& len, int port )
{
    static BroadcastMessage msg;

    msg.broadcastVersion = BroadcastVersion;
    msg.protocolVersion = ProtocolVersion;
    msg.listenPort = port;

    memcpy( msg.programName, procname, pnsz );
    memset( msg.programName + pnsz, 0, WelcomeMessageProgramNameSize - pnsz );

    len = int( offsetof( BroadcastMessage, programName ) + pnsz + 1 );
    return msg;
}

#if defined _WIN32 || defined __CYGWIN__
static DWORD s_profilerThreadId = 0;
static char s_crashText[1024];

LONG WINAPI CrashFilter( PEXCEPTION_POINTERS pExp )
{
    if( !GetProfiler().IsConnected() ) return EXCEPTION_CONTINUE_SEARCH;

    const unsigned ec = pExp->ExceptionRecord->ExceptionCode;
    auto msgPtr = s_crashText;
    switch( ec )
    {
    case EXCEPTION_ACCESS_VIOLATION:
        msgPtr += sprintf( msgPtr, "Exception EXCEPTION_ACCESS_VIOLATION (0x%x). ", ec );
        switch( pExp->ExceptionRecord->ExceptionInformation[0] )
        {
        case 0:
            msgPtr += sprintf( msgPtr, "Read violation at address 0x%" PRIxPTR ".", pExp->ExceptionRecord->ExceptionInformation[1] );
            break;
        case 1:
            msgPtr += sprintf( msgPtr, "Write violation at address 0x%" PRIxPTR ".", pExp->ExceptionRecord->ExceptionInformation[1] );
            break;
        case 8:
            msgPtr += sprintf( msgPtr, "DEP violation at address 0x%" PRIxPTR ".", pExp->ExceptionRecord->ExceptionInformation[1] );
            break;
        default:
            break;
        }
        break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        msgPtr += sprintf( msgPtr, "Exception EXCEPTION_ARRAY_BOUNDS_EXCEEDED (0x%x). ", ec );
        break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:
        msgPtr += sprintf( msgPtr, "Exception EXCEPTION_DATATYPE_MISALIGNMENT (0x%x). ", ec );
        break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        msgPtr += sprintf( msgPtr, "Exception EXCEPTION_FLT_DIVIDE_BY_ZERO (0x%x). ", ec );
        break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
        msgPtr += sprintf( msgPtr, "Exception EXCEPTION_ILLEGAL_INSTRUCTION (0x%x). ", ec );
        break;
    case EXCEPTION_IN_PAGE_ERROR:
        msgPtr += sprintf( msgPtr, "Exception EXCEPTION_IN_PAGE_ERROR (0x%x). ", ec );
        break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
        msgPtr += sprintf( msgPtr, "Exception EXCEPTION_INT_DIVIDE_BY_ZERO (0x%x). ", ec );
        break;
    case EXCEPTION_PRIV_INSTRUCTION:
        msgPtr += sprintf( msgPtr, "Exception EXCEPTION_PRIV_INSTRUCTION (0x%x). ", ec );
        break;
    case EXCEPTION_STACK_OVERFLOW:
        msgPtr += sprintf( msgPtr, "Exception EXCEPTION_STACK_OVERFLOW (0x%x). ", ec );
        break;
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }

    {
        GetProfiler().SendCallstack( 60, "KiUserExceptionDispatcher" );

        TracyLfqPrepare( QueueType::CrashReport );
        item->crashReport.time = Profiler::GetTime();
        item->crashReport.text = (uint64_t)s_crashText;
        TracyLfqCommit;
    }

    HANDLE h = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
    if( h == INVALID_HANDLE_VALUE ) return EXCEPTION_CONTINUE_SEARCH;

    THREADENTRY32 te = { sizeof( te ) };
    if( !Thread32First( h, &te ) )
    {
        CloseHandle( h );
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const auto pid = GetCurrentProcessId();
    const auto tid = GetCurrentThreadId();

    do
    {
        if( te.th32OwnerProcessID == pid && te.th32ThreadID != tid && te.th32ThreadID != s_profilerThreadId )
        {
            HANDLE th = OpenThread( THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID );
            if( th != INVALID_HANDLE_VALUE )
            {
                SuspendThread( th );
                CloseHandle( th );
            }
        }
    }
    while( Thread32Next( h, &te ) );
    CloseHandle( h );

    {
        TracyLfqPrepare( QueueType::Crash );
        TracyLfqCommit;
    }

    std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) );
    GetProfiler().RequestShutdown();
    while( !GetProfiler().HasShutdownFinished() ) { std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) ); };

    TerminateProcess( GetCurrentProcess(), 1 );

    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

#ifdef __linux__
static long s_profilerTid = 0;
static char s_crashText[1024];
static std::atomic<bool> s_alreadyCrashed( false );

static void ThreadFreezer( int /*signal*/ )
{
    for(;;) sleep( 1000 );
}

static inline void HexPrint( char*& ptr, uint64_t val )
{
    if( val == 0 )
    {
        *ptr++ = '0';
        return;
    }

    static const char HexTable[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    char buf[16];
    auto bptr = buf;

    do
    {
        *bptr++ = HexTable[val%16];
        val /= 16;
    }
    while( val > 0 );

    do
    {
        *ptr++ = *--bptr;
    }
    while( bptr != buf );
}

static void CrashHandler( int signal, siginfo_t* info, void* /*ucontext*/ )
{
    bool expected = false;
    if( !s_alreadyCrashed.compare_exchange_strong( expected, true ) ) ThreadFreezer( signal );

    auto msgPtr = s_crashText;
    switch( signal )
    {
    case SIGILL:
        strcpy( msgPtr, "Illegal Instruction.\n" );
        while( *msgPtr ) msgPtr++;
        switch( info->si_code )
        {
        case ILL_ILLOPC:
            strcpy( msgPtr, "Illegal opcode.\n" );
            break;
        case ILL_ILLOPN:
            strcpy( msgPtr, "Illegal operand.\n" );
            break;
        case ILL_ILLADR:
            strcpy( msgPtr, "Illegal addressing mode.\n" );
            break;
        case ILL_ILLTRP:
            strcpy( msgPtr, "Illegal trap.\n" );
            break;
        case ILL_PRVOPC:
            strcpy( msgPtr, "Privileged opcode.\n" );
            break;
        case ILL_PRVREG:
            strcpy( msgPtr, "Privileged register.\n" );
            break;
        case ILL_COPROC:
            strcpy( msgPtr, "Coprocessor error.\n" );
            break;
        case ILL_BADSTK:
            strcpy( msgPtr, "Internal stack error.\n" );
            break;
        default:
            break;
        }
        break;
    case SIGFPE:
        strcpy( msgPtr, "Floating-point exception.\n" );
        while( *msgPtr ) msgPtr++;
        switch( info->si_code )
        {
        case FPE_INTDIV:
            strcpy( msgPtr, "Integer divide by zero.\n" );
            break;
        case FPE_INTOVF:
            strcpy( msgPtr, "Integer overflow.\n" );
            break;
        case FPE_FLTDIV:
            strcpy( msgPtr, "Floating-point divide by zero.\n" );
            break;
        case FPE_FLTOVF:
            strcpy( msgPtr, "Floating-point overflow.\n" );
            break;
        case FPE_FLTUND:
            strcpy( msgPtr, "Floating-point underflow.\n" );
            break;
        case FPE_FLTRES:
            strcpy( msgPtr, "Floating-point inexact result.\n" );
            break;
        case FPE_FLTINV:
            strcpy( msgPtr, "Floating-point invalid operation.\n" );
            break;
        case FPE_FLTSUB:
            strcpy( msgPtr, "Subscript out of range.\n" );
            break;
        default:
            break;
        }
        break;
    case SIGSEGV:
        strcpy( msgPtr, "Invalid memory reference.\n" );
        while( *msgPtr ) msgPtr++;
        switch( info->si_code )
        {
        case SEGV_MAPERR:
            strcpy( msgPtr, "Address not mapped to object.\n" );
            break;
        case SEGV_ACCERR:
            strcpy( msgPtr, "Invalid permissions for mapped object.\n" );
            break;
#  ifdef SEGV_BNDERR
        case SEGV_BNDERR:
            strcpy( msgPtr, "Failed address bound checks.\n" );
            break;
#  endif
#  ifdef SEGV_PKUERR
        case SEGV_PKUERR:
            strcpy( msgPtr, "Access was denied by memory protection keys.\n" );
            break;
#  endif
        default:
            break;
        }
        break;
    case SIGPIPE:
        strcpy( msgPtr, "Broken pipe.\n" );
        while( *msgPtr ) msgPtr++;
        break;
    case SIGBUS:
        strcpy( msgPtr, "Bus error.\n" );
        while( *msgPtr ) msgPtr++;
        switch( info->si_code )
        {
        case BUS_ADRALN:
            strcpy( msgPtr, "Invalid address alignment.\n" );
            break;
        case BUS_ADRERR:
            strcpy( msgPtr, "Nonexistent physical address.\n" );
            break;
        case BUS_OBJERR:
            strcpy( msgPtr, "Object-specific hardware error.\n" );
            break;
#  ifdef BUS_MCEERR_AR
        case BUS_MCEERR_AR:
            strcpy( msgPtr, "Hardware memory error consumed on a machine check; action required.\n" );
            break;
#  endif
#  ifdef BUS_MCEERR_AO
        case BUS_MCEERR_AO:
            strcpy( msgPtr, "Hardware memory error detected in process but not consumed; action optional.\n" );
            break;
#  endif
        default:
            break;
        }
        break;
    default:
        abort();
    }
    while( *msgPtr ) msgPtr++;

    if( signal != SIGPIPE )
    {
        strcpy( msgPtr, "Fault address: 0x" );
        while( *msgPtr ) msgPtr++;
        HexPrint( msgPtr, uint64_t( info->si_addr ) );
        *msgPtr++ = '\n';
    }

    {
        GetProfiler().SendCallstack( 60, "__kernel_rt_sigreturn" );

        TracyLfqPrepare( QueueType::CrashReport );
        item->crashReport.time = Profiler::GetTime();
        item->crashReport.text = (uint64_t)s_crashText;
        TracyLfqCommit;
    }

    DIR* dp = opendir( "/proc/self/task" );
    if( !dp ) abort();

    const auto selfTid = syscall( SYS_gettid );

    struct dirent* ep;
    while( ( ep = readdir( dp ) ) != nullptr )
    {
        if( ep->d_name[0] == '.' ) continue;
        int tid = atoi( ep->d_name );
        if( tid != selfTid && tid != s_profilerTid )
        {
            syscall( SYS_tkill, tid, SIGPWR );
        }
    }
    closedir( dp );

    {
        TracyLfqPrepare( QueueType::Crash );
        TracyLfqCommit;
    }

    std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) );
    GetProfiler().RequestShutdown();
    while( !GetProfiler().HasShutdownFinished() ) { std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) ); };

    abort();
}
#endif


enum { QueuePrealloc = 256 * 1024 };

static Profiler* s_instance = nullptr;
static Thread* s_thread;
static Thread* s_compressThread;

#ifdef TRACY_HAS_SYSTEM_TRACING
static Thread* s_sysTraceThread = nullptr;
#endif

TRACY_API bool ProfilerAvailable() { return s_instance != nullptr; }

TRACY_API int64_t GetFrequencyQpc()
{
#if defined _WIN32 || defined __CYGWIN__
    LARGE_INTEGER t;
    QueryPerformanceFrequency( &t );
    return t.QuadPart;
#else
    return 0;
#endif
}

#ifdef TRACY_DELAYED_INIT
struct ThreadNameData;
TRACY_API moodycamel::ConcurrentQueue<QueueItem>& GetQueue();
TRACY_API void InitRPMallocThread();

void InitRPMallocThread()
{
    RPMallocInit rpinit;
    rpmalloc_thread_initialize();
}

struct ProfilerData
{
    int64_t initTime = SetupHwTimer();
    RPMallocInit rpmalloc_init;
    moodycamel::ConcurrentQueue<QueueItem> queue;
    Profiler profiler;
    std::atomic<uint32_t> lockCounter { 0 };
    std::atomic<uint8_t> gpuCtxCounter { 0 };
    std::atomic<ThreadNameData*> threadNameData { nullptr };
};

struct ProducerWrapper
{
    ProducerWrapper( ProfilerData& data ) : detail( data.queue ), ptr( data.queue.get_explicit_producer( detail ) ) {}
    moodycamel::ProducerToken detail;
    tracy::moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* ptr;
};

struct ProfilerThreadData
{
    ProfilerThreadData( ProfilerData& data ) : token( data ), gpuCtx( { nullptr } ) {}
    RPMallocInit rpmalloc_init;
    ProducerWrapper token;
    GpuCtxWrapper gpuCtx;
#  ifdef TRACY_ON_DEMAND
    LuaZoneState luaZoneState;
#  endif
};

#  ifdef TRACY_MANUAL_LIFETIME
ProfilerData* s_profilerData = nullptr;
TRACY_API void StartupProfiler()
{
    s_profilerData = new ProfilerData;
    s_profilerData->profiler.SpawnWorkerThreads();
}
static ProfilerData& GetProfilerData()
{
    assert(s_profilerData);
    return *s_profilerData;
}
TRACY_API void ShutdownProfiler()
{
    delete s_profilerData;
    s_profilerData = nullptr;
    rpmalloc_finalize();
}
#  else
static std::atomic<int> profilerDataLock { 0 };
static std::atomic<ProfilerData*> profilerData { nullptr };

static ProfilerData& GetProfilerData()
{
    auto ptr = profilerData.load( std::memory_order_acquire );
    if( !ptr )
    {
        int expected = 0;
        while( !profilerDataLock.compare_exchange_strong( expected, 1, std::memory_order_release, std::memory_order_relaxed ) ) { expected = 0; }
        ptr = profilerData.load( std::memory_order_acquire );
        if( !ptr )
        {
            ptr = (ProfilerData*)malloc( sizeof( ProfilerData ) );
            new (ptr) ProfilerData();
            profilerData.store( ptr, std::memory_order_release );
        }
        profilerDataLock.store( 0, std::memory_order_release );
    }
    return *ptr;
}
#  endif

static ProfilerThreadData& GetProfilerThreadData()
{
    thread_local ProfilerThreadData data( GetProfilerData() );
    return data;
}

TRACY_API moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* GetToken() { return GetProfilerThreadData().token.ptr; }
TRACY_API Profiler& GetProfiler() { return GetProfilerData().profiler; }
TRACY_API moodycamel::ConcurrentQueue<QueueItem>& GetQueue() { return GetProfilerData().queue; }
TRACY_API int64_t GetInitTime() { return GetProfilerData().initTime; }
TRACY_API std::atomic<uint32_t>& GetLockCounter() { return GetProfilerData().lockCounter; }
TRACY_API std::atomic<uint8_t>& GetGpuCtxCounter() { return GetProfilerData().gpuCtxCounter; }
TRACY_API GpuCtxWrapper& GetGpuCtx() { return GetProfilerThreadData().gpuCtx; }
TRACY_API uint64_t GetThreadHandle() { return detail::GetThreadHandleImpl(); }
std::atomic<ThreadNameData*>& GetThreadNameData() { return GetProfilerData().threadNameData; }

#  ifdef TRACY_ON_DEMAND
TRACY_API LuaZoneState& GetLuaZoneState() { return GetProfilerThreadData().luaZoneState; }
#  endif

#  ifndef TRACY_MANUAL_LIFETIME
namespace
{
    const auto& __profiler_init = GetProfiler();
}
#  endif

#else
TRACY_API void InitRPMallocThread()
{
    rpmalloc_thread_initialize();
}

// MSVC static initialization order solution. gcc/clang uses init_order() to avoid all this.

// 1a. But s_queue is needed for initialization of variables in point 2.
extern moodycamel::ConcurrentQueue<QueueItem> s_queue;

thread_local RPMallocInit init_order(106) s_rpmalloc_thread_init;

// 2. If these variables would be in the .CRT$XCB section, they would be initialized only in main thread.
thread_local moodycamel::ProducerToken init_order(107) s_token_detail( s_queue );
thread_local ProducerWrapper init_order(108) s_token { s_queue.get_explicit_producer( s_token_detail ) };
thread_local ThreadHandleWrapper init_order(104) s_threadHandle { detail::GetThreadHandleImpl() };

#  ifdef _MSC_VER
// 1. Initialize these static variables before all other variables.
#    pragma warning( disable : 4075 )
#    pragma init_seg( ".CRT$XCB" )
#  endif

static InitTimeWrapper init_order(101) s_initTime { SetupHwTimer() };
static RPMallocInit init_order(102) s_rpmalloc_init;
moodycamel::ConcurrentQueue<QueueItem> init_order(103) s_queue( QueuePrealloc );
std::atomic<uint32_t> init_order(104) s_lockCounter( 0 );
std::atomic<uint8_t> init_order(104) s_gpuCtxCounter( 0 );

thread_local GpuCtxWrapper init_order(104) s_gpuCtx { nullptr };

struct ThreadNameData;
static std::atomic<ThreadNameData*> init_order(104) s_threadNameDataInstance( nullptr );
std::atomic<ThreadNameData*>& s_threadNameData = s_threadNameDataInstance;

#  ifdef TRACY_ON_DEMAND
thread_local LuaZoneState init_order(104) s_luaZoneState { 0, false };
#  endif

static Profiler init_order(105) s_profiler;

TRACY_API moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* GetToken() { return s_token.ptr; }
TRACY_API Profiler& GetProfiler() { return s_profiler; }
TRACY_API moodycamel::ConcurrentQueue<QueueItem>& GetQueue() { return s_queue; }
TRACY_API int64_t GetInitTime() { return s_initTime.val; }
TRACY_API std::atomic<uint32_t>& GetLockCounter() { return s_lockCounter; }
TRACY_API std::atomic<uint8_t>& GetGpuCtxCounter() { return s_gpuCtxCounter; }
TRACY_API GpuCtxWrapper& GetGpuCtx() { return s_gpuCtx; }
#  ifdef __CYGWIN__
// Hackfix for cygwin reporting memory frees without matching allocations. WTF?
TRACY_API uint64_t GetThreadHandle() { return detail::GetThreadHandleImpl(); }
#  else
TRACY_API uint64_t GetThreadHandle() { return s_threadHandle.val; }
#  endif

std::atomic<ThreadNameData*>& GetThreadNameData() { return s_threadNameData; }

#  ifdef TRACY_ON_DEMAND
TRACY_API LuaZoneState& GetLuaZoneState() { return s_luaZoneState; }
#  endif
#endif

Profiler::Profiler()
    : m_timeBegin( 0 )
    , m_mainThread( detail::GetThreadHandleImpl() )
    , m_epoch( std::chrono::duration_cast<std::chrono::seconds>( std::chrono::system_clock::now().time_since_epoch() ).count() )
    , m_shutdown( false )
    , m_shutdownManual( false )
    , m_shutdownFinished( false )
    , m_sock( nullptr )
    , m_broadcast( nullptr )
    , m_noExit( false )
    , m_userPort( 0 )
    , m_zoneId( 1 )
    , m_samplingPeriod( 0 )
    , m_stream( LZ4_createStream() )
    , m_buffer( (char*)tracy_malloc( TargetFrameSize*3 ) )
    , m_bufferOffset( 0 )
    , m_bufferStart( 0 )
    , m_lz4Buf( (char*)tracy_malloc( LZ4Size + sizeof( lz4sz_t ) ) )
    , m_serialQueue( 1024*1024 )
    , m_serialDequeue( 1024*1024 )
    , m_fiQueue( 16 )
    , m_fiDequeue( 16 )
    , m_frameCount( 0 )
    , m_isConnected( false )
#ifdef TRACY_ON_DEMAND
    , m_connectionId( 0 )
    , m_deferredQueue( 64*1024 )
#endif
    , m_paramCallback( nullptr )
{
    assert( !s_instance );
    s_instance = this;

#ifndef TRACY_DELAYED_INIT
#  ifdef _MSC_VER
    // 3. But these variables need to be initialized in main thread within the .CRT$XCB section. Do it here.
    s_token_detail = moodycamel::ProducerToken( s_queue );
    s_token = ProducerWrapper { s_queue.get_explicit_producer( s_token_detail ) };
    s_threadHandle = ThreadHandleWrapper { m_mainThread };
#  endif
#endif

    CalibrateTimer();
    CalibrateDelay();
    ReportTopology();

#ifndef TRACY_NO_EXIT
    const char* noExitEnv = getenv( "TRACY_NO_EXIT" );
    if( noExitEnv && noExitEnv[0] == '1' )
    {
        m_noExit = true;
    }
#endif

    const char* userPort = getenv( "TRACY_PORT" );
    if( userPort )
    {
        m_userPort = atoi( userPort );
    }

#if !defined(TRACY_DELAYED_INIT) || !defined(TRACY_MANUAL_LIFETIME)
    SpawnWorkerThreads();
#endif
}

void Profiler::SpawnWorkerThreads()
{
    s_thread = (Thread*)tracy_malloc( sizeof( Thread ) );
    new(s_thread) Thread( LaunchWorker, this );

    s_compressThread = (Thread*)tracy_malloc( sizeof( Thread ) );
    new(s_compressThread) Thread( LaunchCompressWorker, this );

#ifdef TRACY_HAS_SYSTEM_TRACING
    if( SysTraceStart( m_samplingPeriod ) )
    {
        s_sysTraceThread = (Thread*)tracy_malloc( sizeof( Thread ) );
        new(s_sysTraceThread) Thread( SysTraceWorker, nullptr );
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
    }
#endif

#if defined _WIN32 || defined __CYGWIN__
    s_profilerThreadId = GetThreadId( s_thread->Handle() );
    AddVectoredExceptionHandler( 1, CrashFilter );
#endif

#ifdef __linux__
    struct sigaction threadFreezer = {};
    threadFreezer.sa_handler = ThreadFreezer;
    sigaction( SIGPWR, &threadFreezer, nullptr );

    struct sigaction crashHandler = {};
    crashHandler.sa_sigaction = CrashHandler;
    crashHandler.sa_flags = SA_SIGINFO;
    sigaction( SIGILL, &crashHandler, nullptr );
    sigaction( SIGFPE, &crashHandler, nullptr );
    sigaction( SIGSEGV, &crashHandler, nullptr );
    sigaction( SIGPIPE, &crashHandler, nullptr );
    sigaction( SIGBUS, &crashHandler, nullptr );
#endif

#ifdef TRACY_HAS_CALLSTACK
    InitCallstack();
#endif

    m_timeBegin.store( GetTime(), std::memory_order_relaxed );
}

Profiler::~Profiler()
{
    m_shutdown.store( true, std::memory_order_relaxed );

#ifdef TRACY_HAS_SYSTEM_TRACING
    if( s_sysTraceThread )
    {
        SysTraceStop();
        s_sysTraceThread->~Thread();
        tracy_free( s_sysTraceThread );
    }
#endif

    s_compressThread->~Thread();
    tracy_free( s_compressThread );
    s_thread->~Thread();
    tracy_free( s_thread );

    tracy_free( m_lz4Buf );
    tracy_free( m_buffer );
    LZ4_freeStream( (LZ4_stream_t*)m_stream );

    if( m_sock )
    {
        m_sock->~Socket();
        tracy_free( m_sock );
    }

    if( m_broadcast )
    {
        m_broadcast->~UdpBroadcast();
        tracy_free( m_broadcast );
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
#ifdef __linux__
    s_profilerTid = syscall( SYS_gettid );
#endif

    ThreadExitHandler threadExitHandler;

    SetThreadName( "Tracy Profiler" );

#ifdef TRACY_DATA_PORT
    const bool dataPortSearch = false;
    auto dataPort = m_userPort != 0 ? m_userPort : TRACY_DATA_PORT;
#else
    const bool dataPortSearch = m_userPort == 0;
    auto dataPort = m_userPort != 0 ? m_userPort : 8086;
#endif
#ifdef TRACY_BROADCAST_PORT
    const auto broadcastPort = TRACY_BROADCAST_PORT;
#else
    const auto broadcastPort = 8086;
#endif

    while( m_timeBegin.load( std::memory_order_relaxed ) == 0 ) std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );

    rpmalloc_thread_initialize();

    const auto procname = GetProcessName();
    const auto pnsz = std::min<size_t>( strlen( procname ), WelcomeMessageProgramNameSize - 1 );

    const auto hostinfo = GetHostInfo();
    const auto hisz = std::min<size_t>( strlen( hostinfo ), WelcomeMessageHostInfoSize - 1 );

    const uint64_t pid = GetPid();

#ifdef TRACY_ON_DEMAND
    uint8_t onDemand = 1;
#else
    uint8_t onDemand = 0;
#endif

#ifdef __APPLE__
    uint8_t isApple = 1;
#else
    uint8_t isApple = 0;
#endif

#if defined __i386 || defined _M_IX86
    uint8_t cpuArch = CpuArchX86;
#elif defined __x86_64__ || defined _M_X64
    uint8_t cpuArch = CpuArchX64;
#elif defined __aarch64__
    uint8_t cpuArch = CpuArchArm64;
#elif defined __ARM_ARCH
    uint8_t cpuArch = CpuArchArm32;
#else
    uint8_t cpuArch = CpuArchUnknown;
#endif

#ifdef TRACY_NO_CODE_TRANSFER
    uint8_t codeTransfer = 0;
#else
    uint8_t codeTransfer = 1;
#endif

#if defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64
    uint32_t regs[4];
    char manufacturer[12];
    CpuId( regs, 0 );
    memcpy( manufacturer, regs+1, 4 );
    memcpy( manufacturer+4, regs+3, 4 );
    memcpy( manufacturer+8, regs+2, 4 );

    CpuId( regs, 1 );
    uint32_t cpuId = ( regs[0] & 0xFFF ) | ( ( regs[0] & 0xFFF0000 ) >> 4 );
#else
    const char manufacturer[12] = {};
    uint32_t cpuId = 0;
#endif

    WelcomeMessage welcome;
    MemWrite( &welcome.timerMul, m_timerMul );
    MemWrite( &welcome.initBegin, GetInitTime() );
    MemWrite( &welcome.initEnd, m_timeBegin.load( std::memory_order_relaxed ) );
    MemWrite( &welcome.delay, m_delay );
    MemWrite( &welcome.resolution, m_resolution );
    MemWrite( &welcome.epoch, m_epoch );
    MemWrite( &welcome.pid, pid );
    MemWrite( &welcome.samplingPeriod, m_samplingPeriod );
    MemWrite( &welcome.onDemand, onDemand );
    MemWrite( &welcome.isApple, isApple );
    MemWrite( &welcome.cpuArch, cpuArch );
    MemWrite( &welcome.codeTransfer, codeTransfer );
    memcpy( welcome.cpuManufacturer, manufacturer, 12 );
    MemWrite( &welcome.cpuId, cpuId );
    memcpy( welcome.programName, procname, pnsz );
    memset( welcome.programName + pnsz, 0, WelcomeMessageProgramNameSize - pnsz );
    memcpy( welcome.hostInfo, hostinfo, hisz );
    memset( welcome.hostInfo + hisz, 0, WelcomeMessageHostInfoSize - hisz );

    moodycamel::ConsumerToken token( GetQueue() );

    ListenSocket listen;
    bool isListening = false;
    if( !dataPortSearch )
    {
        isListening = listen.Listen( dataPort, 4 );
    }
    else
    {
        for( uint32_t i=0; i<20; i++ )
        {
            if( listen.Listen( dataPort+i, 4 ) )
            {
                dataPort += i;
                isListening = true;
                break;
            }
        }
    }
    if( !isListening )
    {
        for(;;)
        {
            if( ShouldExit() )
            {
                m_shutdownFinished.store( true, std::memory_order_relaxed );
                return;
            }

            ClearQueues( token );
            std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
        }
    }

#ifndef TRACY_NO_BROADCAST
    m_broadcast = (UdpBroadcast*)tracy_malloc( sizeof( UdpBroadcast ) );
    new(m_broadcast) UdpBroadcast();
#  ifdef TRACY_ONLY_LOCALHOST
    const char* addr = "127.255.255.255";
#  else
    const char* addr = "255.255.255.255";
#  endif
    if( !m_broadcast->Open( addr, broadcastPort ) )
    {
        m_broadcast->~UdpBroadcast();
        tracy_free( m_broadcast );
        m_broadcast = nullptr;
    }
#endif

    int broadcastLen = 0;
    auto& broadcastMsg = GetBroadcastMessage( procname, pnsz, broadcastLen, dataPort );
    uint64_t lastBroadcast = 0;

    // Connections loop.
    // Each iteration of the loop handles whole connection. Multiple iterations will only
    // happen in the on-demand mode or when handshake fails.
    for(;;)
    {
        // Wait for incoming connection
        for(;;)
        {
#ifndef TRACY_NO_EXIT
            if( !m_noExit && ShouldExit() )
            {
                if( m_broadcast )
                {
                    broadcastMsg.activeTime = -1;
                    m_broadcast->Send( broadcastPort, &broadcastMsg, broadcastLen );
                }
                m_shutdownFinished.store( true, std::memory_order_relaxed );
                return;
            }
#endif
            m_sock = listen.Accept();
            if( m_sock ) break;
#ifndef TRACY_ON_DEMAND
            ProcessSysTime();
#endif

            if( m_broadcast )
            {
                const auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
                if( t - lastBroadcast > 3000000000 )  // 3s
                {
                    lastBroadcast = t;
                    const auto ts = std::chrono::duration_cast<std::chrono::seconds>( std::chrono::system_clock::now().time_since_epoch() ).count();
                    broadcastMsg.activeTime = int32_t( ts - m_epoch );
                    assert( broadcastMsg.activeTime >= 0 );
                    m_broadcast->Send( broadcastPort, &broadcastMsg, broadcastLen );
                }
            }
        }

        if( m_broadcast )
        {
            lastBroadcast = 0;
            broadcastMsg.activeTime = -1;
            m_broadcast->Send( broadcastPort, &broadcastMsg, broadcastLen );
        }

        // Handshake
        {
            char shibboleth[HandshakeShibbolethSize];
            auto res = m_sock->ReadRaw( shibboleth, HandshakeShibbolethSize, 2000 );
            if( !res || memcmp( shibboleth, HandshakeShibboleth, HandshakeShibbolethSize ) != 0 )
            {
                m_sock->~Socket();
                tracy_free( m_sock );
                m_sock = nullptr;
                continue;
            }

            uint32_t protocolVersion;
            res = m_sock->ReadRaw( &protocolVersion, sizeof( protocolVersion ), 2000 );
            if( !res )
            {
                m_sock->~Socket();
                tracy_free( m_sock );
                m_sock = nullptr;
                continue;
            }

            if( protocolVersion != ProtocolVersion )
            {
                HandshakeStatus status = HandshakeProtocolMismatch;
                m_sock->Send( &status, sizeof( status ) );
                m_sock->~Socket();
                tracy_free( m_sock );
                m_sock = nullptr;
                continue;
            }
        }

#ifdef TRACY_ON_DEMAND
        const auto currentTime = GetTime();
        ClearQueues( token );
        m_connectionId.fetch_add( 1, std::memory_order_release );
#endif
        m_isConnected.store( true, std::memory_order_release );

        HandshakeStatus handshake = HandshakeWelcome;
        m_sock->Send( &handshake, sizeof( handshake ) );

        LZ4_resetStream( (LZ4_stream_t*)m_stream );
        m_sock->Send( &welcome, sizeof( welcome ) );

        m_threadCtx = 0;
        m_refTimeSerial = 0;
        m_refTimeCtx = 0;
        m_refTimeGpu = 0;

#ifdef TRACY_ON_DEMAND
        OnDemandPayloadMessage onDemand;
        onDemand.frames = m_frameCount.load( std::memory_order_relaxed );
        onDemand.currentTime = currentTime;

        m_sock->Send( &onDemand, sizeof( onDemand ) );

        m_deferredLock.lock();
        for( auto& item : m_deferredQueue )
        {
            uint64_t ptr;
            uint16_t size;
            const auto idx = MemRead<uint8_t>( &item.hdr.idx );
            switch( (QueueType)idx )
            {
            case QueueType::MessageAppInfo:
                ptr = MemRead<uint64_t>( &item.messageFat.text );
                size = MemRead<uint16_t>( &item.messageFat.size );
                SendSingleString( (const char*)ptr, size );
                break;
            case QueueType::LockName:
                ptr = MemRead<uint64_t>( &item.lockNameFat.name );
                size = MemRead<uint16_t>( &item.lockNameFat.size );
                SendSingleString( (const char*)ptr, size );
                break;
            default:
                break;
            }
            AppendData( &item, QueueDataSize[idx] );
        }
        m_deferredLock.unlock();
#endif

        // Main communications loop
        int keepAlive = 0;
        for(;;)
        {
            ProcessSysTime();
            const auto status = Dequeue( token );
            const auto serialStatus = DequeueSerial();
            if( status == DequeueStatus::ConnectionLost || serialStatus == DequeueStatus::ConnectionLost )
            {
                break;
            }
            else if( status == DequeueStatus::QueueEmpty && serialStatus == DequeueStatus::QueueEmpty )
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

            bool connActive = true;
            while( m_sock->HasData() && connActive )
            {
                connActive = HandleServerQuery();
            }
            if( !connActive ) break;
        }
        if( ShouldExit() ) break;

        m_isConnected.store( false, std::memory_order_release );
#ifdef TRACY_ON_DEMAND
        m_bufferOffset = 0;
        m_bufferStart = 0;
#endif

        m_sock->~Socket();
        tracy_free( m_sock );
        m_sock = nullptr;

#ifndef TRACY_ON_DEMAND
        // Client is no longer available here. Accept incoming connections, but reject handshake.
        for(;;)
        {
            if( ShouldExit() )
            {
                m_shutdownFinished.store( true, std::memory_order_relaxed );
                return;
            }

            ClearQueues( token );

            m_sock = listen.Accept();
            if( m_sock )
            {
                char shibboleth[HandshakeShibbolethSize];
                auto res = m_sock->ReadRaw( shibboleth, HandshakeShibbolethSize, 1000 );
                if( !res || memcmp( shibboleth, HandshakeShibboleth, HandshakeShibbolethSize ) != 0 )
                {
                    m_sock->~Socket();
                    tracy_free( m_sock );
                    m_sock = nullptr;
                    continue;
                }

                uint32_t protocolVersion;
                res = m_sock->ReadRaw( &protocolVersion, sizeof( protocolVersion ), 1000 );
                if( !res )
                {
                    m_sock->~Socket();
                    tracy_free( m_sock );
                    m_sock = nullptr;
                    continue;
                }

                HandshakeStatus status = HandshakeNotAvailable;
                m_sock->Send( &status, sizeof( status ) );
                m_sock->~Socket();
                tracy_free( m_sock );
            }
        }
#endif
    }
    // End of connections loop

    // Client is exiting. Send items remaining in queues.
    for(;;)
    {
        const auto status = Dequeue( token );
        const auto serialStatus = DequeueSerial();
        if( status == DequeueStatus::ConnectionLost || serialStatus == DequeueStatus::ConnectionLost )
        {
            m_shutdownFinished.store( true, std::memory_order_relaxed );
            return;
        }
        else if( status == DequeueStatus::QueueEmpty && serialStatus == DequeueStatus::QueueEmpty )
        {
            if( m_bufferOffset != m_bufferStart ) CommitData();
            break;
        }

        while( m_sock->HasData() )
        {
            if( !HandleServerQuery() )
            {
                m_shutdownFinished.store( true, std::memory_order_relaxed );
                return;
            }
        }
    }

    // Send client termination notice to the server
    QueueItem terminate;
    MemWrite( &terminate.hdr.type, QueueType::Terminate );
    if( !SendData( (const char*)&terminate, 1 ) )
    {
        m_shutdownFinished.store( true, std::memory_order_relaxed );
        return;
    }
    // Handle remaining server queries
    for(;;)
    {
        if( m_sock->HasData() )
        {
            while( m_sock->HasData() )
            {
                if( !HandleServerQuery() )
                {
                    m_shutdownFinished.store( true, std::memory_order_relaxed );
                    return;
                }
            }
            while( Dequeue( token ) == DequeueStatus::DataDequeued ) {}
            while( DequeueSerial() == DequeueStatus::DataDequeued ) {}
            if( m_bufferOffset != m_bufferStart )
            {
                if( !CommitData() )
                {
                    m_shutdownFinished.store( true, std::memory_order_relaxed );
                    return;
                }
            }
        }
        else
        {
            if( m_bufferOffset != m_bufferStart ) CommitData();
            std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
        }
    }
}

void Profiler::CompressWorker()
{
    ThreadExitHandler threadExitHandler;

    SetThreadName( "Tracy DXT1" );
    while( m_timeBegin.load( std::memory_order_relaxed ) == 0 ) std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
    rpmalloc_thread_initialize();
    for(;;)
    {
        const auto shouldExit = ShouldExit();

        {
            bool lockHeld = true;
            while( !m_fiLock.try_lock() )
            {
                if( m_shutdownManual.load( std::memory_order_relaxed ) )
                {
                    lockHeld = false;
                    break;
                }
            }
            if( !m_fiQueue.empty() ) m_fiQueue.swap( m_fiDequeue );
            if( lockHeld )
            {
                m_fiLock.unlock();
            }
        }

        const auto sz = m_fiDequeue.size();
        if( sz > 0 )
        {
            auto fi = m_fiDequeue.data();
            auto end = fi + sz;
            while( fi != end )
            {
                const auto w = fi->w;
                const auto h = fi->h;
                const auto csz = size_t( w * h / 2 );
                auto etc1buf = (char*)tracy_malloc( csz );
                CompressImageDxt1( (const char*)fi->image, etc1buf, w, h );
                tracy_free( fi->image );

                TracyLfqPrepare( QueueType::FrameImage );
                MemWrite( &item->frameImageFat.image, (uint64_t)etc1buf );
                MemWrite( &item->frameImageFat.frame, fi->frame );
                MemWrite( &item->frameImageFat.w, w );
                MemWrite( &item->frameImageFat.h, h );
                uint8_t flip = fi->flip;
                MemWrite( &item->frameImageFat.flip, flip );
                TracyLfqCommit;

                fi++;
            }
            m_fiDequeue.clear();
        }
        else
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 20 ) );
        }

        if( shouldExit )
        {
            return;
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
        ptr = MemRead<uint64_t>( &item.zoneTextFat.text );
        tracy_free( (void*)ptr );
        break;
    case QueueType::MessageColor:
    case QueueType::MessageColorCallstack:
        ptr = MemRead<uint64_t>( &item.messageColorFat.text );
        tracy_free( (void*)ptr );
        break;
    case QueueType::Message:
    case QueueType::MessageCallstack:
#ifndef TRACY_ON_DEMAND
    case QueueType::MessageAppInfo:
#endif
        ptr = MemRead<uint64_t>( &item.messageFat.text );
        tracy_free( (void*)ptr );
        break;
    case QueueType::ZoneBeginAllocSrcLoc:
    case QueueType::ZoneBeginAllocSrcLocCallstack:
        ptr = MemRead<uint64_t>( &item.zoneBegin.srcloc );
        tracy_free( (void*)ptr );
        break;
    case QueueType::GpuZoneBeginAllocSrcLoc:
    case QueueType::GpuZoneBeginAllocSrcLocCallstack:
    case QueueType::GpuZoneBeginAllocSrcLocSerial:
    case QueueType::GpuZoneBeginAllocSrcLocCallstackSerial:
        ptr = MemRead<uint64_t>( &item.gpuZoneBegin.srcloc );
        tracy_free( (void*)ptr );
        break;
    case QueueType::CallstackSerial:
    case QueueType::Callstack:
        ptr = MemRead<uint64_t>( &item.callstackFat.ptr );
        tracy_free( (void*)ptr );
        break;
    case QueueType::CallstackAlloc:
        ptr = MemRead<uint64_t>( &item.callstackAllocFat.nativePtr );
        tracy_free( (void*)ptr );
        ptr = MemRead<uint64_t>( &item.callstackAllocFat.ptr );
        tracy_free( (void*)ptr );
        break;
    case QueueType::CallstackSample:
        ptr = MemRead<uint64_t>( &item.callstackSampleFat.ptr );
        tracy_free( (void*)ptr );
        break;
    case QueueType::FrameImage:
        ptr = MemRead<uint64_t>( &item.frameImageFat.image );
        tracy_free( (void*)ptr );
        break;
#ifndef TRACY_ON_DEMAND
    case QueueType::LockName:
        ptr = MemRead<uint64_t>( &item.lockNameFat.name );
        tracy_free( (void*)ptr );
        break;
#endif
#ifdef TRACY_ON_DEMAND
    case QueueType::MessageAppInfo:
        // Don't free memory associated with deferred messages.
        break;
#endif
    default:
        break;
    }
}

void Profiler::ClearQueues( moodycamel::ConsumerToken& token )
{
    for(;;)
    {
        const auto sz = GetQueue().try_dequeue_bulk_single( token, [](const uint64_t&){}, []( QueueItem* item, size_t sz ) { assert( sz > 0 ); while( sz-- > 0 ) FreeAssociatedMemory( *item++ ); } );
        if( sz == 0 ) break;
    }

    ClearSerial();
}

void Profiler::ClearSerial()
{
    bool lockHeld = true;
    while( !m_serialLock.try_lock() )
    {
        if( m_shutdownManual.load( std::memory_order_relaxed ) )
        {
            lockHeld = false;
            break;
        }
    }
    for( auto& v : m_serialQueue ) FreeAssociatedMemory( v );
    m_serialQueue.clear();
    if( lockHeld )
    {
        m_serialLock.unlock();
    }

    for( auto& v : m_serialDequeue ) FreeAssociatedMemory( v );
    m_serialDequeue.clear();
}

Profiler::DequeueStatus Profiler::Dequeue( moodycamel::ConsumerToken& token )
{
    bool connectionLost = false;
    const auto sz = GetQueue().try_dequeue_bulk_single( token,
        [this, &connectionLost] ( const uint64_t& threadId )
        {
            if( threadId != m_threadCtx )
            {
                QueueItem item;
                MemWrite( &item.hdr.type, QueueType::ThreadContext );
                MemWrite( &item.threadCtx.thread, threadId );
                if( !AppendData( &item, QueueDataSize[(int)QueueType::ThreadContext] ) ) connectionLost = true;
                m_threadCtx = threadId;
                m_refTimeThread = 0;
            }
        },
        [this, &connectionLost] ( QueueItem* item, size_t sz )
        {
            if( connectionLost ) return;
            assert( sz > 0 );
            int64_t refThread = m_refTimeThread;
            int64_t refCtx = m_refTimeCtx;
            int64_t refGpu = m_refTimeGpu;
            while( sz-- > 0 )
            {
                uint64_t ptr;
                uint16_t size;
                auto idx = MemRead<uint8_t>( &item->hdr.idx );
                if( idx < (int)QueueType::Terminate )
                {
                    switch( (QueueType)idx )
                    {
                    case QueueType::ZoneText:
                    case QueueType::ZoneName:
                        ptr = MemRead<uint64_t>( &item->zoneTextFat.text );
                        size = MemRead<uint16_t>( &item->zoneTextFat.size );
                        SendSingleString( (const char*)ptr, size );
                        tracy_free( (void*)ptr );
                        break;
                    case QueueType::Message:
                    case QueueType::MessageCallstack:
                        ptr = MemRead<uint64_t>( &item->messageFat.text );
                        size = MemRead<uint16_t>( &item->messageFat.size );
                        SendSingleString( (const char*)ptr, size );
                        tracy_free( (void*)ptr );
                        break;
                    case QueueType::MessageColor:
                    case QueueType::MessageColorCallstack:
                        ptr = MemRead<uint64_t>( &item->messageColorFat.text );
                        size = MemRead<uint16_t>( &item->messageColorFat.size );
                        SendSingleString( (const char*)ptr, size );
                        tracy_free( (void*)ptr );
                        break;
                    case QueueType::MessageAppInfo:
                        ptr = MemRead<uint64_t>( &item->messageFat.text );
                        size = MemRead<uint16_t>( &item->messageFat.size );
                        SendSingleString( (const char*)ptr, size );
#ifndef TRACY_ON_DEMAND
                        tracy_free( (void*)ptr );
#endif
                        break;
                    case QueueType::ZoneBeginAllocSrcLoc:
                    case QueueType::ZoneBeginAllocSrcLocCallstack:
                    {
                        int64_t t = MemRead<int64_t>( &item->zoneBegin.time );
                        int64_t dt = t - refThread;
                        refThread = t;
                        MemWrite( &item->zoneBegin.time, dt );
                        ptr = MemRead<uint64_t>( &item->zoneBegin.srcloc );
                        SendSourceLocationPayload( ptr );
                        tracy_free( (void*)ptr );
                        break;
                    }
                    case QueueType::Callstack:
                        ptr = MemRead<uint64_t>( &item->callstackFat.ptr );
                        SendCallstackPayload( ptr );
                        tracy_free( (void*)ptr );
                        break;
                    case QueueType::CallstackAlloc:
                        ptr = MemRead<uint64_t>( &item->callstackAllocFat.nativePtr );
                        if( ptr != 0 )
                        {
                            CutCallstack( (void*)ptr, "lua_pcall" );
                            SendCallstackPayload( ptr );
                            tracy_free( (void*)ptr );
                        }
                        ptr = MemRead<uint64_t>( &item->callstackAllocFat.ptr );
                        SendCallstackAlloc( ptr );
                        tracy_free( (void*)ptr );
                        break;
                    case QueueType::CallstackSample:
                    {
                        ptr = MemRead<uint64_t>( &item->callstackSampleFat.ptr );
                        SendCallstackPayload64( ptr );
                        tracy_free( (void*)ptr );
                        int64_t t = MemRead<int64_t>( &item->callstackSampleFat.time );
                        int64_t dt = t - refCtx;
                        refCtx = t;
                        MemWrite( &item->callstackSampleFat.time, dt );
                        break;
                    }
                    case QueueType::FrameImage:
                    {
                        ptr = MemRead<uint64_t>( &item->frameImageFat.image );
                        const auto w = MemRead<uint16_t>( &item->frameImageFat.w );
                        const auto h = MemRead<uint16_t>( &item->frameImageFat.h );
                        const auto csz = size_t( w * h / 2 );
                        SendLongString( ptr, (const char*)ptr, csz, QueueType::FrameImageData );
                        tracy_free( (void*)ptr );
                        break;
                    }
                    case QueueType::ZoneBegin:
                    case QueueType::ZoneBeginCallstack:
                    {
                        int64_t t = MemRead<int64_t>( &item->zoneBegin.time );
                        int64_t dt = t - refThread;
                        refThread = t;
                        MemWrite( &item->zoneBegin.time, dt );
                        break;
                    }
                    case QueueType::ZoneEnd:
                    {
                        int64_t t = MemRead<int64_t>( &item->zoneEnd.time );
                        int64_t dt = t - refThread;
                        refThread = t;
                        MemWrite( &item->zoneEnd.time, dt );
                        break;
                    }
                    case QueueType::GpuZoneBegin:
                    case QueueType::GpuZoneBeginCallstack:
                    {
                        int64_t t = MemRead<int64_t>( &item->gpuZoneBegin.cpuTime );
                        int64_t dt = t - refThread;
                        refThread = t;
                        MemWrite( &item->gpuZoneBegin.cpuTime, dt );
                        break;
                    }
                    case QueueType::GpuZoneBeginAllocSrcLoc:
                    case QueueType::GpuZoneBeginAllocSrcLocCallstack:
                    {
                        int64_t t = MemRead<int64_t>( &item->gpuZoneBegin.cpuTime );
                        int64_t dt = t - refThread;
                        refThread = t;
                        MemWrite( &item->gpuZoneBegin.cpuTime, dt );
                        ptr = MemRead<uint64_t>( &item->gpuZoneBegin.srcloc );
                        SendSourceLocationPayload( ptr );
                        tracy_free( (void*)ptr );
                        break;
                    }
                    case QueueType::GpuZoneEnd:
                    {
                        int64_t t = MemRead<int64_t>( &item->gpuZoneEnd.cpuTime );
                        int64_t dt = t - refThread;
                        refThread = t;
                        MemWrite( &item->gpuZoneEnd.cpuTime, dt );
                        break;
                    }
                    case QueueType::PlotData:
                    {
                        int64_t t = MemRead<int64_t>( &item->plotData.time );
                        int64_t dt = t - refThread;
                        refThread = t;
                        MemWrite( &item->plotData.time, dt );
                        break;
                    }
                    case QueueType::ContextSwitch:
                    {
                        int64_t t = MemRead<int64_t>( &item->contextSwitch.time );
                        int64_t dt = t - refCtx;
                        refCtx = t;
                        MemWrite( &item->contextSwitch.time, dt );
                        break;
                    }
                    case QueueType::ThreadWakeup:
                    {
                        int64_t t = MemRead<int64_t>( &item->threadWakeup.time );
                        int64_t dt = t - refCtx;
                        refCtx = t;
                        MemWrite( &item->threadWakeup.time, dt );
                        break;
                    }
                    case QueueType::GpuTime:
                    {
                        int64_t t = MemRead<int64_t>( &item->gpuTime.gpuTime );
                        int64_t dt = t - refGpu;
                        refGpu = t;
                        MemWrite( &item->gpuTime.gpuTime, dt );
                        break;
                    }
                    default:
                        assert( false );
                        break;
                    }
                }
                if( !AppendData( item++, QueueDataSize[idx] ) )
                {
                    connectionLost = true;
                    m_refTimeThread = refThread;
                    m_refTimeCtx = refCtx;
                    m_refTimeGpu = refGpu;
                    return;
                }
            }
            m_refTimeThread = refThread;
            m_refTimeCtx = refCtx;
            m_refTimeGpu = refGpu;
        }
    );
    if( connectionLost ) return DequeueStatus::ConnectionLost;
    return sz > 0 ? DequeueStatus::DataDequeued : DequeueStatus::QueueEmpty;
}

Profiler::DequeueStatus Profiler::DequeueContextSwitches( tracy::moodycamel::ConsumerToken& token, int64_t& timeStop )
{
    const auto sz = GetQueue().try_dequeue_bulk_single( token, [] ( const uint64_t& ) {},
        [this, &timeStop] ( QueueItem* item, size_t sz )
        {
            assert( sz > 0 );
            int64_t refCtx = m_refTimeCtx;
            while( sz-- > 0 )
            {
                FreeAssociatedMemory( *item );
                if( timeStop < 0 ) return;
                const auto idx = MemRead<uint8_t>( &item->hdr.idx );
                if( idx == (uint8_t)QueueType::ContextSwitch )
                {
                    const auto csTime = MemRead<int64_t>( &item->contextSwitch.time );
                    if( csTime > timeStop )
                    {
                        timeStop = -1;
                        m_refTimeCtx = refCtx;
                        return;
                    }
                    int64_t dt = csTime - refCtx;
                    refCtx = csTime;
                    MemWrite( &item->contextSwitch.time, dt );
                    if( !AppendData( item, QueueDataSize[(int)QueueType::ContextSwitch] ) )
                    {
                        timeStop = -2;
                        m_refTimeCtx = refCtx;
                        return;
                    }
                }
                else if( idx == (uint8_t)QueueType::ThreadWakeup )
                {
                    const auto csTime = MemRead<int64_t>( &item->threadWakeup.time );
                    if( csTime > timeStop )
                    {
                        timeStop = -1;
                        m_refTimeCtx = refCtx;
                        return;
                    }
                    int64_t dt = csTime - refCtx;
                    refCtx = csTime;
                    MemWrite( &item->threadWakeup.time, dt );
                    if( !AppendData( item, QueueDataSize[(int)QueueType::ThreadWakeup] ) )
                    {
                        timeStop = -2;
                        m_refTimeCtx = refCtx;
                        return;
                    }
                }
                item++;
            }
            m_refTimeCtx = refCtx;
        }
    );

    if( timeStop == -2 ) return DequeueStatus::ConnectionLost;
    return ( timeStop == -1 || sz > 0 ) ? DequeueStatus::DataDequeued : DequeueStatus::QueueEmpty;
}

Profiler::DequeueStatus Profiler::DequeueSerial()
{
    {
        bool lockHeld = true;
        while( !m_serialLock.try_lock() )
        {
            if( m_shutdownManual.load( std::memory_order_relaxed ) )
            {
                lockHeld = false;
                break;
            }
        }
        if( !m_serialQueue.empty() ) m_serialQueue.swap( m_serialDequeue );
        if( lockHeld )
        {
            m_serialLock.unlock();
        }
    }

    const auto sz = m_serialDequeue.size();
    if( sz > 0 )
    {
        int64_t refSerial = m_refTimeSerial;
        int64_t refGpu = m_refTimeGpu;
        auto item = m_serialDequeue.data();
        auto end = item + sz;
        while( item != end )
        {
            uint64_t ptr;
            auto idx = MemRead<uint8_t>( &item->hdr.idx );
            if( idx < (int)QueueType::Terminate )
            {
                switch( (QueueType)idx )
                {
                case QueueType::CallstackSerial:
                    ptr = MemRead<uint64_t>( &item->callstackFat.ptr );
                    SendCallstackPayload( ptr );
                    tracy_free( (void*)ptr );
                    break;
                case QueueType::LockWait:
                case QueueType::LockSharedWait:
                {
                    int64_t t = MemRead<int64_t>( &item->lockWait.time );
                    int64_t dt = t - refSerial;
                    refSerial = t;
                    MemWrite( &item->lockWait.time, dt );
                    break;
                }
                case QueueType::LockObtain:
                case QueueType::LockSharedObtain:
                {
                    int64_t t = MemRead<int64_t>( &item->lockObtain.time );
                    int64_t dt = t - refSerial;
                    refSerial = t;
                    MemWrite( &item->lockObtain.time, dt );
                    break;
                }
                case QueueType::LockRelease:
                case QueueType::LockSharedRelease:
                {
                    int64_t t = MemRead<int64_t>( &item->lockRelease.time );
                    int64_t dt = t - refSerial;
                    refSerial = t;
                    MemWrite( &item->lockRelease.time, dt );
                    break;
                }
                case QueueType::LockName:
                {
                    ptr = MemRead<uint64_t>( &item->lockNameFat.name );
                    uint16_t size = MemRead<uint16_t>( &item->lockNameFat.size );
                    SendSingleString( (const char*)ptr, size );
#ifndef TRACY_ON_DEMAND
                    tracy_free( (void*)ptr );
#endif
                    break;
                }
                case QueueType::MemAlloc:
                case QueueType::MemAllocNamed:
                case QueueType::MemAllocCallstack:
                case QueueType::MemAllocCallstackNamed:
                {
                    int64_t t = MemRead<int64_t>( &item->memAlloc.time );
                    int64_t dt = t - refSerial;
                    refSerial = t;
                    MemWrite( &item->memAlloc.time, dt );
                    break;
                }
                case QueueType::MemFree:
                case QueueType::MemFreeNamed:
                case QueueType::MemFreeCallstack:
                case QueueType::MemFreeCallstackNamed:
                {
                    int64_t t = MemRead<int64_t>( &item->memFree.time );
                    int64_t dt = t - refSerial;
                    refSerial = t;
                    MemWrite( &item->memFree.time, dt );
                    break;
                }
                case QueueType::GpuZoneBeginSerial:
                case QueueType::GpuZoneBeginCallstackSerial:
                {
                    int64_t t = MemRead<int64_t>( &item->gpuZoneBegin.cpuTime );
                    int64_t dt = t - refSerial;
                    refSerial = t;
                    MemWrite( &item->gpuZoneBegin.cpuTime, dt );
                    break;
                }
                case QueueType::GpuZoneBeginAllocSrcLocSerial:
                case QueueType::GpuZoneBeginAllocSrcLocCallstackSerial:
                {
                    int64_t t = MemRead<int64_t>( &item->gpuZoneBegin.cpuTime );
                    int64_t dt = t - refSerial;
                    refSerial = t;
                    MemWrite( &item->gpuZoneBegin.cpuTime, dt );
                    ptr = MemRead<uint64_t>( &item->gpuZoneBegin.srcloc );
                    SendSourceLocationPayload( ptr );
                    tracy_free( (void*)ptr );
                    break;
                }
                case QueueType::GpuZoneEndSerial:
                {
                    int64_t t = MemRead<int64_t>( &item->gpuZoneEnd.cpuTime );
                    int64_t dt = t - refSerial;
                    refSerial = t;
                    MemWrite( &item->gpuZoneEnd.cpuTime, dt );
                    break;
                }
                case QueueType::GpuTime:
                {
                    int64_t t = MemRead<int64_t>( &item->gpuTime.gpuTime );
                    int64_t dt = t - refGpu;
                    refGpu = t;
                    MemWrite( &item->gpuTime.gpuTime, dt );
                    break;
                }
                default:
                    assert( false );
                    break;
                }
            }
            if( !AppendData( item, QueueDataSize[idx] ) ) return DequeueStatus::ConnectionLost;
            item++;
        }
        m_refTimeSerial = refSerial;
        m_refTimeGpu = refGpu;
        m_serialDequeue.clear();
    }
    else
    {
        return DequeueStatus::QueueEmpty;
    }
    return DequeueStatus::DataDequeued;
}

bool Profiler::CommitData()
{
    bool ret = SendData( m_buffer + m_bufferStart, m_bufferOffset - m_bufferStart );
    if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;
    m_bufferStart = m_bufferOffset;
    return ret;
}

bool Profiler::SendData( const char* data, size_t len )
{
    const lz4sz_t lz4sz = LZ4_compress_fast_continue( (LZ4_stream_t*)m_stream, data, m_lz4Buf + sizeof( lz4sz_t ), (int)len, LZ4Size, 1 );
    memcpy( m_lz4Buf, &lz4sz, sizeof( lz4sz ) );
    return m_sock->Send( m_lz4Buf, lz4sz + sizeof( lz4sz_t ) ) != -1;
}

void Profiler::SendString( uint64_t str, const char* ptr, size_t len, QueueType type )
{
    assert( type == QueueType::StringData ||
            type == QueueType::ThreadName ||
            type == QueueType::PlotName ||
            type == QueueType::FrameName ||
            type == QueueType::ExternalName ||
            type == QueueType::ExternalThreadName );

    QueueItem item;
    MemWrite( &item.hdr.type, type );
    MemWrite( &item.stringTransfer.ptr, str );

    assert( len <= std::numeric_limits<uint16_t>::max() );
    auto l16 = uint16_t( len );

    NeedDataSize( QueueDataSize[(int)type] + sizeof( l16 ) + l16 );

    AppendDataUnsafe( &item, QueueDataSize[(int)type] );
    AppendDataUnsafe( &l16, sizeof( l16 ) );
    AppendDataUnsafe( ptr, l16 );
}

void Profiler::SendSingleString( const char* ptr, size_t len )
{
    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::SingleStringData );

    assert( len <= std::numeric_limits<uint16_t>::max() );
    auto l16 = uint16_t( len );

    NeedDataSize( QueueDataSize[(int)QueueType::SingleStringData] + sizeof( l16 ) + l16 );

    AppendDataUnsafe( &item, QueueDataSize[(int)QueueType::SingleStringData] );
    AppendDataUnsafe( &l16, sizeof( l16 ) );
    AppendDataUnsafe( ptr, l16 );
}

void Profiler::SendSecondString( const char* ptr, size_t len )
{
    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::SecondStringData );

    assert( len <= std::numeric_limits<uint16_t>::max() );
    auto l16 = uint16_t( len );

    NeedDataSize( QueueDataSize[(int)QueueType::SecondStringData] + sizeof( l16 ) + l16 );

    AppendDataUnsafe( &item, QueueDataSize[(int)QueueType::SecondStringData] );
    AppendDataUnsafe( &l16, sizeof( l16 ) );
    AppendDataUnsafe( ptr, l16 );
}

void Profiler::SendLongString( uint64_t str, const char* ptr, size_t len, QueueType type )
{
    assert( type == QueueType::FrameImageData ||
            type == QueueType::SymbolCode );

    QueueItem item;
    MemWrite( &item.hdr.type, type );
    MemWrite( &item.stringTransfer.ptr, str );

    assert( len <= std::numeric_limits<uint32_t>::max() );
    assert( QueueDataSize[(int)type] + sizeof( uint32_t ) + len <= TargetFrameSize );
    auto l32 = uint32_t( len );

    NeedDataSize( QueueDataSize[(int)type] + sizeof( l32 ) + l32 );

    AppendDataUnsafe( &item, QueueDataSize[(int)type] );
    AppendDataUnsafe( &l32, sizeof( l32 ) );
    AppendDataUnsafe( ptr, l32 );
}

void Profiler::SendSourceLocation( uint64_t ptr )
{
    auto srcloc = (const SourceLocationData*)ptr;
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

    uint16_t len;
    memcpy( &len, ptr, sizeof( len ) );
    assert( len > 2 );
    len -= 2;
    ptr += 2;

    NeedDataSize( QueueDataSize[(int)QueueType::SourceLocationPayload] + sizeof( len ) + len );

    AppendDataUnsafe( &item, QueueDataSize[(int)QueueType::SourceLocationPayload] );
    AppendDataUnsafe( &len, sizeof( len ) );
    AppendDataUnsafe( ptr, len );
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

    if( compile_time_condition<sizeof( uintptr_t ) == sizeof( uint64_t )>::value )
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

void Profiler::SendCallstackPayload64( uint64_t _ptr )
{
    auto ptr = (uint64_t*)_ptr;

    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::CallstackPayload );
    MemWrite( &item.stringTransfer.ptr, _ptr );

    const auto sz = *ptr++;
    const auto len = sz * sizeof( uint64_t );
    const auto l16 = uint16_t( len );

    NeedDataSize( QueueDataSize[(int)QueueType::CallstackPayload] + sizeof( l16 ) + l16 );

    AppendDataUnsafe( &item, QueueDataSize[(int)QueueType::CallstackPayload] );
    AppendDataUnsafe( &l16, sizeof( l16 ) );
    AppendDataUnsafe( ptr, sizeof( uint64_t ) * sz );
}

void Profiler::SendCallstackAlloc( uint64_t _ptr )
{
    auto ptr = (const char*)_ptr;

    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::CallstackAllocPayload );
    MemWrite( &item.stringTransfer.ptr, _ptr );

    uint16_t len;
    memcpy( &len, ptr, 2 );
    ptr += 2;

    NeedDataSize( QueueDataSize[(int)QueueType::CallstackAllocPayload] + sizeof( len ) + len );

    AppendDataUnsafe( &item, QueueDataSize[(int)QueueType::CallstackAllocPayload] );
    AppendDataUnsafe( &len, sizeof( len ) );
    AppendDataUnsafe( ptr, len );
}

void Profiler::SendCallstackFrame( uint64_t ptr )
{
#ifdef TRACY_HAS_CALLSTACK
    const auto frameData = DecodeCallstackPtr( ptr );

    {
        SendSingleString( frameData.imageName );

        QueueItem item;
        MemWrite( &item.hdr.type, QueueType::CallstackFrameSize );
        MemWrite( &item.callstackFrameSize.ptr, ptr );
        MemWrite( &item.callstackFrameSize.size, frameData.size );

        AppendData( &item, QueueDataSize[(int)QueueType::CallstackFrameSize] );
    }

    for( uint8_t i=0; i<frameData.size; i++ )
    {
        const auto& frame = frameData.data[i];

        SendSingleString( frame.name );
        SendSecondString( frame.file );

        QueueItem item;
        MemWrite( &item.hdr.type, QueueType::CallstackFrame );
        MemWrite( &item.callstackFrame.line, frame.line );
        MemWrite( &item.callstackFrame.symAddr, frame.symAddr );
        MemWrite( &item.callstackFrame.symLen, frame.symLen );

        AppendData( &item, QueueDataSize[(int)QueueType::CallstackFrame] );

        tracy_free( (void*)frame.name );
        tracy_free( (void*)frame.file );
    }
#endif
}


bool Profiler::HandleServerQuery()
{
    ServerQueryPacket payload;
    if( !m_sock->Read( &payload, sizeof( payload ), 10 ) ) return false;

    uint8_t type;
    uint64_t ptr;
    uint32_t extra;
    memcpy( &type, &payload.type, sizeof( payload.type ) );
    memcpy( &ptr, &payload.ptr, sizeof( payload.ptr ) );
    memcpy( &extra, &payload.extra, sizeof( payload.extra ) );

    switch( type )
    {
    case ServerQueryString:
        SendString( ptr, (const char*)ptr, QueueType::StringData );
        break;
    case ServerQueryThreadString:
        if( ptr == m_mainThread )
        {
            SendString( ptr, "Main thread", 11, QueueType::ThreadName );
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
    case ServerQueryFrameName:
        SendString( ptr, (const char*)ptr, QueueType::FrameName );
        break;
    case ServerQueryDisconnect:
        HandleDisconnect();
        return false;
#ifdef TRACY_HAS_SYSTEM_TRACING
    case ServerQueryExternalName:
        SysTraceSendExternalName( ptr );
        break;
#endif
    case ServerQueryParameter:
        HandleParameter( ptr );
        break;
    case ServerQuerySymbol:
        HandleSymbolQuery( ptr );
        break;
#ifndef TRACY_NO_CODE_TRANSFER
    case ServerQuerySymbolCode:
        HandleSymbolCodeQuery( ptr, extra );
        break;
#endif
    case ServerQueryCodeLocation:
        SendCodeLocation( ptr );
        break;
    default:
        assert( false );
        break;
    }

    return true;
}

void Profiler::HandleDisconnect()
{
    moodycamel::ConsumerToken token( GetQueue() );

#ifdef TRACY_HAS_SYSTEM_TRACING
    if( s_sysTraceThread )
    {
        auto timestamp = GetTime();
        for(;;)
        {
            const auto status = DequeueContextSwitches( token, timestamp );
            if( status == DequeueStatus::ConnectionLost )
            {
                return;
            }
            else if( status == DequeueStatus::QueueEmpty )
            {
                if( m_bufferOffset != m_bufferStart )
                {
                    if( !CommitData() ) return;
                }
            }
            if( timestamp < 0 )
            {
                if( m_bufferOffset != m_bufferStart )
                {
                    if( !CommitData() ) return;
                }
                break;
            }
            ClearSerial();
            if( m_sock->HasData() )
            {
                while( m_sock->HasData() )
                {
                    if( !HandleServerQuery() ) return;
                }
                if( m_bufferOffset != m_bufferStart )
                {
                    if( !CommitData() ) return;
                }
            }
            else
            {
                if( m_bufferOffset != m_bufferStart )
                {
                    if( !CommitData() ) return;
                }
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }
        }
    }
#endif

    QueueItem terminate;
    MemWrite( &terminate.hdr.type, QueueType::Terminate );
    if( !SendData( (const char*)&terminate, 1 ) ) return;
    for(;;)
    {
        ClearQueues( token );
        if( m_sock->HasData() )
        {
            while( m_sock->HasData() )
            {
                if( !HandleServerQuery() ) return;
            }
            if( m_bufferOffset != m_bufferStart )
            {
                if( !CommitData() ) return;
            }
        }
        else
        {
            if( m_bufferOffset != m_bufferStart )
            {
                if( !CommitData() ) return;
            }
            std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
        }
    }
}

void Profiler::CalibrateTimer()
{
#ifdef TRACY_HW_TIMER
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

void Profiler::CalibrateDelay()
{
    constexpr int Iterations = 50000;

    auto mindiff = std::numeric_limits<int64_t>::max();
    for( int i=0; i<Iterations * 10; i++ )
    {
        const auto t0i = GetTime();
        const auto t1i = GetTime();
        const auto dti = t1i - t0i;
        if( dti > 0 && dti < mindiff ) mindiff = dti;
    }
    m_resolution = mindiff;

#ifdef TRACY_DELAYED_INIT
    m_delay = m_resolution;
#else
    constexpr int Events = Iterations * 2;   // start + end
    static_assert( Events < QueuePrealloc, "Delay calibration loop will allocate memory in queue" );

    static const tracy::SourceLocationData __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 };
    const auto t0 = GetTime();
    for( int i=0; i<Iterations; i++ )
    {
        {
            TracyLfqPrepare( QueueType::ZoneBegin );
            MemWrite( &item->zoneBegin.time, Profiler::GetTime() );
            MemWrite( &item->zoneBegin.srcloc, (uint64_t)&__tracy_source_location );
            TracyLfqCommit;
        }
        {
            TracyLfqPrepare( QueueType::ZoneEnd );
            MemWrite( &item->zoneEnd.time, GetTime() );
            TracyLfqCommit;
        }
    }
    const auto t1 = GetTime();
    const auto dt = t1 - t0;
    m_delay = dt / Events;

    moodycamel::ConsumerToken token( GetQueue() );
    int left = Events;
    while( left != 0 )
    {
        const auto sz = GetQueue().try_dequeue_bulk_single( token, [](const uint64_t&){}, [](QueueItem* item, size_t sz){} );
        assert( sz > 0 );
        left -= (int)sz;
    }
    assert( GetQueue().size_approx() == 0 );
#endif
}

void Profiler::ReportTopology()
{
#ifndef TRACY_DELAYED_INIT
    struct CpuData
    {
        uint32_t package;
        uint32_t core;
        uint32_t thread;
    };

#if defined _WIN32 || defined __CYGWIN__
    t_GetLogicalProcessorInformationEx _GetLogicalProcessorInformationEx = (t_GetLogicalProcessorInformationEx)GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "GetLogicalProcessorInformationEx" );
    if( !_GetLogicalProcessorInformationEx ) return;

    DWORD psz = 0;
    _GetLogicalProcessorInformationEx( RelationProcessorPackage, nullptr, &psz );
    auto packageInfo = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)tracy_malloc( psz );
    auto res = _GetLogicalProcessorInformationEx( RelationProcessorPackage, packageInfo, &psz );
    assert( res );

    DWORD csz = 0;
    _GetLogicalProcessorInformationEx( RelationProcessorCore, nullptr, &csz );
    auto coreInfo = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)tracy_malloc( csz );
    res = _GetLogicalProcessorInformationEx( RelationProcessorCore, coreInfo, &csz );
    assert( res );

    SYSTEM_INFO sysinfo;
    GetSystemInfo( &sysinfo );
    const uint32_t numcpus = sysinfo.dwNumberOfProcessors;

    auto cpuData = (CpuData*)tracy_malloc( sizeof( CpuData ) * numcpus );
    for( uint32_t i=0; i<numcpus; i++ ) cpuData[i].thread = i;

    int idx = 0;
    auto ptr = packageInfo;
    while( (char*)ptr < ((char*)packageInfo) + psz )
    {
        assert( ptr->Relationship == RelationProcessorPackage );
        // FIXME account for GroupCount
        auto mask = ptr->Processor.GroupMask[0].Mask;
        int core = 0;
        while( mask != 0 )
        {
            if( mask & 1 ) cpuData[core].package = idx;
            core++;
            mask >>= 1;
        }
        ptr = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)(((char*)ptr) + ptr->Size);
        idx++;
    }

    idx = 0;
    ptr = coreInfo;
    while( (char*)ptr < ((char*)coreInfo) + csz )
    {
        assert( ptr->Relationship == RelationProcessorCore );
        // FIXME account for GroupCount
        auto mask = ptr->Processor.GroupMask[0].Mask;
        int core = 0;
        while( mask != 0 )
        {
            if( mask & 1 ) cpuData[core].core = idx;
            core++;
            mask >>= 1;
        }
        ptr = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)(((char*)ptr) + ptr->Size);
        idx++;
    }

    for( uint32_t i=0; i<numcpus; i++ )
    {
        auto& data = cpuData[i];

        TracyLfqPrepare( QueueType::CpuTopology );
        MemWrite( &item->cpuTopology.package, data.package );
        MemWrite( &item->cpuTopology.core, data.core );
        MemWrite( &item->cpuTopology.thread, data.thread );

#ifdef TRACY_ON_DEMAND
        DeferItem( *item );
#endif

        TracyLfqCommit;
    }

    tracy_free( cpuData );
    tracy_free( coreInfo );
    tracy_free( packageInfo );
#elif defined __linux__
    const int numcpus = std::thread::hardware_concurrency();
    auto cpuData = (CpuData*)tracy_malloc( sizeof( CpuData ) * numcpus );
    memset( cpuData, 0, sizeof( CpuData ) * numcpus );

    const char* basePath = "/sys/devices/system/cpu/cpu";
    for( int i=0; i<numcpus; i++ )
    {
        char path[1024];
        sprintf( path, "%s%i/topology/physical_package_id", basePath, i );
        char buf[1024];
        FILE* f = fopen( path, "rb" );
        if( !f )
        {
            tracy_free( cpuData );
            return;
        }
        auto read = fread( buf, 1, 1024, f );
        buf[read] = '\0';
        fclose( f );
        cpuData[i].package = uint32_t( atoi( buf ) );
        cpuData[i].thread = i;
        sprintf( path, "%s%i/topology/core_id", basePath, i );
        f = fopen( path, "rb" );
        read = fread( buf, 1, 1024, f );
        buf[read] = '\0';
        fclose( f );
        cpuData[i].core = uint32_t( atoi( buf ) );
    }

    for( int i=0; i<numcpus; i++ )
    {
        auto& data = cpuData[i];

        TracyLfqPrepare( QueueType::CpuTopology );
        MemWrite( &item->cpuTopology.package, data.package );
        MemWrite( &item->cpuTopology.core, data.core );
        MemWrite( &item->cpuTopology.thread, data.thread );

#ifdef TRACY_ON_DEMAND
        DeferItem( *item );
#endif

        TracyLfqCommit;
    }

    tracy_free( cpuData );
#endif
#endif
}

void Profiler::SendCallstack( int depth, const char* skipBefore )
{
#ifdef TRACY_HAS_CALLSTACK
    TracyLfqPrepare( QueueType::Callstack );
    auto ptr = Callstack( depth );
    CutCallstack( ptr, skipBefore );
    MemWrite( &item->callstackFat.ptr, (uint64_t)ptr );
    TracyLfqCommit;
#endif
}

void Profiler::CutCallstack( void* callstack, const char* skipBefore )
{
#ifdef TRACY_HAS_CALLSTACK
    auto data = (uintptr_t*)callstack;
    const auto sz = *data++;
    uintptr_t i;
    for( i=0; i<sz; i++ )
    {
        auto name = DecodeCallstackPtrFast( uint64_t( data[i] ) );
        const bool found = strcmp( name, skipBefore ) == 0;
        if( found )
        {
            i++;
            break;
        }
    }

    if( i != sz )
    {
        memmove( data, data + i, ( sz - i ) * sizeof( uintptr_t* ) );
        *--data = sz - i;
    }
#endif
}

#ifdef TRACY_HAS_SYSTIME
void Profiler::ProcessSysTime()
{
    if( m_shutdown.load( std::memory_order_relaxed ) ) return;
    auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    if( t - m_sysTimeLast > 100000000 )    // 100 ms
    {
        auto sysTime = m_sysTime.Get();
        if( sysTime >= 0 )
        {
            m_sysTimeLast = t;

            TracyLfqPrepare( QueueType::SysTimeReport );
            MemWrite( &item->sysTime.time, GetTime() );
            MemWrite( &item->sysTime.sysTime, sysTime );
            TracyLfqCommit;
        }
    }
}
#endif

void Profiler::HandleParameter( uint64_t payload )
{
    assert( m_paramCallback );
    const auto idx = uint32_t( payload >> 32 );
    const auto val = int32_t( payload & 0xFFFFFFFF );
    m_paramCallback( idx, val );
    TracyLfqPrepare( QueueType::ParamPingback );
    TracyLfqCommit;
}

#ifdef __ANDROID__
// Implementation helpers of EnsureReadable(address).
// This is so far only needed on Android, where it is common for libraries to be mapped
// with only executable, not readable, permissions. Typical example (line from /proc/self/maps):
/*
746b63b000-746b6dc000 --xp 00042000 07:48 35                             /apex/com.android.runtime/lib64/bionic/libc.so
*/
// See https://github.com/wolfpld/tracy/issues/125 .
// To work around this, we parse /proc/self/maps and we use mprotect to set read permissions
// on any mappings that contain symbols addresses hit by HandleSymbolCodeQuery.

namespace {
// Holds some information about a single memory mapping.
struct MappingInfo {
    // Start of address range. Inclusive.
    uintptr_t start_address;
    // End of address range. Exclusive, so the mapping is the half-open interval
    // [start, end) and its length in bytes is `end - start`. As in /proc/self/maps.
    uintptr_t end_address;
    // Read/Write/Executable permissions.
    bool perm_r, perm_w, perm_x;
};
}  // anonymous namespace

// Internal implementation helper for LookUpMapping(address).
//
// Parses /proc/self/maps returning a vector<MappingInfo>.
// /proc/self/maps is assumed to be sorted by ascending address, so the resulting
// vector is sorted by ascending address too.
static std::vector<MappingInfo> ParseMappings()
{
    std::vector<MappingInfo> result;
    FILE* file = fopen( "/proc/self/maps", "r" );
    if( !file ) return result;
    char line[1024];
    while( fgets( line, sizeof( line ), file ) )
    {
        uintptr_t start_addr;
        uintptr_t end_addr;
        if( sscanf( line, "%lx-%lx", &start_addr, &end_addr ) != 2 ) continue;
        char* first_space = strchr( line, ' ' );
        if( !first_space ) continue;
        char* perm = first_space + 1;
        char* second_space = strchr( perm, ' ' );
        if( !second_space || second_space - perm != 4 ) continue;
        result.emplace_back();
        auto& mapping = result.back();
        mapping.start_address = start_addr;
        mapping.end_address = end_addr;
        mapping.perm_r = perm[0] == 'r';
        mapping.perm_w = perm[1] == 'w';
        mapping.perm_x = perm[2] == 'x';
    }
    fclose( file );
    return result;
}

// Internal implementation helper for LookUpMapping(address).
//
// Takes as input an `address` and a known vector `mappings`, assumed to be
// sorted by increasing addresses, as /proc/self/maps seems to be.
// Returns a pointer to the MappingInfo describing the mapping that this
// address belongs to, or nullptr if the address isn't in `mappings`.
static MappingInfo* LookUpMapping(std::vector<MappingInfo>& mappings, uintptr_t address)
{
    // Comparison function for std::lower_bound. Returns true if all addresses in `m1`
    // are lower than `addr`.
    auto Compare = []( const MappingInfo& m1, uintptr_t addr ) {
        // '<=' because the address ranges are half-open intervals, [start, end).
        return m1.end_address <= addr;
    };
    auto iter = std::lower_bound( mappings.begin(), mappings.end(), address, Compare );
    if( iter == mappings.end() || iter->start_address > address) {
        return nullptr;
    }
    return &*iter;
}

// Internal implementation helper for EnsureReadable(address).
//
// Takes as input an `address` and returns a pointer to a MappingInfo
// describing the mapping that this address belongs to, or nullptr if
// the address isn't in any known mapping.
//
// This function is stateful and not reentrant (assumes to be called from
// only one thread). It holds a vector of mappings parsed from /proc/self/maps.
//
// Attempts to react to mappings changes by re-parsing /proc/self/maps.
static MappingInfo* LookUpMapping(uintptr_t address)
{
    // Static state managed by this function. Not constant, we mutate that state as
    // we turn some mappings readable. Initially parsed once here, updated as needed below.
    static std::vector<MappingInfo> s_mappings = ParseMappings();
    MappingInfo* mapping = LookUpMapping( s_mappings, address );
    if( mapping ) return mapping;

    // This address isn't in any known mapping. Try parsing again, maybe
    // mappings changed.
    s_mappings = ParseMappings();
    return LookUpMapping( s_mappings, address );
}

// Internal implementation helper for EnsureReadable(address).
//
// Attempts to make the specified `mapping` readable if it isn't already.
// Returns true if and only if the mapping is readable.
static bool EnsureReadable( MappingInfo& mapping )
{
    if( mapping.perm_r )
    {
        // The mapping is already readable.
        return true;
    }
    int prot = PROT_READ;
    if( mapping.perm_w ) prot |= PROT_WRITE;
    if( mapping.perm_x ) prot |= PROT_EXEC;
    if( mprotect( reinterpret_cast<void*>( mapping.start_address ),
                  mapping.end_address - mapping.start_address, prot ) == -1 )
    {
        // Failed to make the mapping readable. Shouldn't happen, hasn't
        // been observed yet. If it happened in practice, we should consider
        // adding a bool to MappingInfo to track this to avoid retrying mprotect
        // everytime on such mappings.
        return false;
    }
    // The mapping is now readable. Update `mapping` so the next call will be fast.
    mapping.perm_r = true;
    return true;
}

// Attempts to set the read permission on the entire mapping containing the
// specified address. Returns true if and only if the mapping is now readable.
static bool EnsureReadable( uintptr_t address )
{
    MappingInfo* mapping = LookUpMapping(address);
    return mapping && EnsureReadable( *mapping );
}

#endif  // defined __ANDROID__

void Profiler::HandleSymbolQuery( uint64_t symbol )
{
#ifdef TRACY_HAS_CALLSTACK
#ifdef __ANDROID__
    // On Android it's common for code to be in mappings that are only executable
    // but not readable.
    if( !EnsureReadable( symbol ) )
    {
        return;
    }
#endif
    const auto sym = DecodeSymbolAddress( symbol );

    SendSingleString( sym.file );

    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::SymbolInformation );
    MemWrite( &item.symbolInformation.line, sym.line );
    MemWrite( &item.symbolInformation.symAddr, symbol );

    AppendData( &item, QueueDataSize[(int)QueueType::SymbolInformation] );

    if( sym.needFree ) tracy_free( (void*)sym.file );
#endif
}

void Profiler::HandleSymbolCodeQuery( uint64_t symbol, uint32_t size )
{
#ifdef __ANDROID__
    // On Android it's common for code to be in mappings that are only executable
    // but not readable.
    if( !EnsureReadable( symbol ) )
    {
        return;
    }
#endif
    SendLongString( symbol, (const char*)symbol, size, QueueType::SymbolCode );
}

void Profiler::SendCodeLocation( uint64_t ptr )
{
#ifdef TRACY_HAS_CALLSTACK
    const auto sym = DecodeCodeAddress( ptr );

    SendSingleString( sym.file );

    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::CodeInformation );
    MemWrite( &item.codeInformation.ptr, ptr );
    MemWrite( &item.codeInformation.line, sym.line );

    AppendData( &item, QueueDataSize[(int)QueueType::CodeInformation] );

    if( sym.needFree ) tracy_free( (void*)sym.file );
#endif
}

#if ( defined _WIN32 || defined __CYGWIN__ ) && defined TRACY_TIMER_QPC
int64_t Profiler::GetTimeQpc()
{
    LARGE_INTEGER t;
    QueryPerformanceCounter( &t );
    return t.QuadPart;
}
#endif

}

#ifdef __cplusplus
extern "C" {
#endif

TRACY_API TracyCZoneCtx ___tracy_emit_zone_begin( const struct ___tracy_source_location_data* srcloc, int active )
{
    ___tracy_c_zone_context ctx;
#ifdef TRACY_ON_DEMAND
    ctx.active = active && tracy::GetProfiler().IsConnected();
#else
    ctx.active = active;
#endif
    if( !ctx.active ) return ctx;
    const auto id = tracy::GetProfiler().GetNextZoneId();
    ctx.id = id;

#ifndef TRACY_NO_VERIFY
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.id, id );
        TracyLfqCommitC;
    }
#endif
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneBegin );
        tracy::MemWrite( &item->zoneBegin.time, tracy::Profiler::GetTime() );
        tracy::MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        TracyLfqCommitC;
    }
    return ctx;
}

TRACY_API TracyCZoneCtx ___tracy_emit_zone_begin_callstack( const struct ___tracy_source_location_data* srcloc, int depth, int active )
{
    ___tracy_c_zone_context ctx;
#ifdef TRACY_ON_DEMAND
    ctx.active = active && tracy::GetProfiler().IsConnected();
#else
    ctx.active = active;
#endif
    if( !ctx.active ) return ctx;
    const auto id = tracy::GetProfiler().GetNextZoneId();
    ctx.id = id;

#ifndef TRACY_NO_VERIFY
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.id, id );
        TracyLfqCommitC;
    }
#endif
    tracy::GetProfiler().SendCallstack( depth );
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneBeginCallstack );
        tracy::MemWrite( &item->zoneBegin.time, tracy::Profiler::GetTime() );
        tracy::MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        TracyLfqCommitC;
    }
    return ctx;
}

TRACY_API TracyCZoneCtx ___tracy_emit_zone_begin_alloc( uint64_t srcloc, int active )
{
    ___tracy_c_zone_context ctx;
#ifdef TRACY_ON_DEMAND
    ctx.active = active && tracy::GetProfiler().IsConnected();
#else
    ctx.active = active;
#endif
    if( !ctx.active )
    {
        tracy::tracy_free( (void*)srcloc );
        return ctx;
    }
    const auto id = tracy::GetProfiler().GetNextZoneId();
    ctx.id = id;

#ifndef TRACY_NO_VERIFY
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.id, id );
        TracyLfqCommitC;
    }
#endif
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneBeginAllocSrcLoc );
        tracy::MemWrite( &item->zoneBegin.time, tracy::Profiler::GetTime() );
        tracy::MemWrite( &item->zoneBegin.srcloc, srcloc );
        TracyLfqCommitC;
    }
    return ctx;
}

TRACY_API TracyCZoneCtx ___tracy_emit_zone_begin_alloc_callstack( uint64_t srcloc, int depth, int active )
{
    ___tracy_c_zone_context ctx;
#ifdef TRACY_ON_DEMAND
    ctx.active = active && tracy::GetProfiler().IsConnected();
#else
    ctx.active = active;
#endif
    if( !ctx.active )
    {
        tracy::tracy_free( (void*)srcloc );
        return ctx;
    }
    const auto id = tracy::GetProfiler().GetNextZoneId();
    ctx.id = id;

#ifndef TRACY_NO_VERIFY
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.id, id );
        TracyLfqCommitC;
    }
#endif
    tracy::GetProfiler().SendCallstack( depth );
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneBeginAllocSrcLocCallstack );
        tracy::MemWrite( &item->zoneBegin.time, tracy::Profiler::GetTime() );
        tracy::MemWrite( &item->zoneBegin.srcloc, srcloc );
        TracyLfqCommitC;
    }
    return ctx;
}

TRACY_API void ___tracy_emit_zone_end( TracyCZoneCtx ctx )
{
    if( !ctx.active ) return;
#ifndef TRACY_NO_VERIFY
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.id, ctx.id );
        TracyLfqCommitC;
    }
#endif
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneEnd );
        tracy::MemWrite( &item->zoneEnd.time, tracy::Profiler::GetTime() );
        TracyLfqCommitC;
    }
}

TRACY_API void ___tracy_emit_zone_text( TracyCZoneCtx ctx, const char* txt, size_t size )
{
    assert( size < std::numeric_limits<uint16_t>::max() );
    if( !ctx.active ) return;
    auto ptr = (char*)tracy::tracy_malloc( size );
    memcpy( ptr, txt, size );
#ifndef TRACY_NO_VERIFY
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.id, ctx.id );
        TracyLfqCommitC;
    }
#endif
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneText );
        tracy::MemWrite( &item->zoneTextFat.text, (uint64_t)ptr );
        tracy::MemWrite( &item->zoneTextFat.size, (uint16_t)size );
        TracyLfqCommitC;
    }
}

TRACY_API void ___tracy_emit_zone_name( TracyCZoneCtx ctx, const char* txt, size_t size )
{
    assert( size < std::numeric_limits<uint16_t>::max() );
    if( !ctx.active ) return;
    auto ptr = (char*)tracy::tracy_malloc( size );
    memcpy( ptr, txt, size );
#ifndef TRACY_NO_VERIFY
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.id, ctx.id );
        TracyLfqCommitC;
    }
#endif
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneName );
        tracy::MemWrite( &item->zoneTextFat.text, (uint64_t)ptr );
        tracy::MemWrite( &item->zoneTextFat.size, (uint16_t)size );
        TracyLfqCommitC;
    }
}

TRACY_API void ___tracy_emit_zone_color( TracyCZoneCtx ctx, uint32_t color ) {
    if( !ctx.active ) return;
#ifndef TRACY_NO_VERIFY
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.id, ctx.id );
        TracyLfqCommitC;
    }
#endif
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneColor );
        tracy::MemWrite( &item->zoneColor.r, uint8_t( ( color       ) & 0xFF ) );
        tracy::MemWrite( &item->zoneColor.g, uint8_t( ( color >> 8  ) & 0xFF ) );
        tracy::MemWrite( &item->zoneColor.b, uint8_t( ( color >> 16 ) & 0xFF ) );
        TracyLfqCommitC;
    }
}

TRACY_API void ___tracy_emit_zone_value( TracyCZoneCtx ctx, uint64_t value )
{
    if( !ctx.active ) return;
#ifndef TRACY_NO_VERIFY
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.id, ctx.id );
        TracyLfqCommitC;
    }
#endif
    {
        TracyLfqPrepareC( tracy::QueueType::ZoneValue );
        tracy::MemWrite( &item->zoneValue.value, value );
        TracyLfqCommitC;
    }
}

TRACY_API void ___tracy_emit_memory_alloc( const void* ptr, size_t size, int secure ) { tracy::Profiler::MemAlloc( ptr, size, secure != 0 ); }
TRACY_API void ___tracy_emit_memory_alloc_callstack( const void* ptr, size_t size, int depth, int secure ) { tracy::Profiler::MemAllocCallstack( ptr, size, depth, secure != 0 ); }
TRACY_API void ___tracy_emit_memory_free( const void* ptr, int secure ) { tracy::Profiler::MemFree( ptr, secure != 0 ); }
TRACY_API void ___tracy_emit_memory_free_callstack( const void* ptr, int depth, int secure ) { tracy::Profiler::MemFreeCallstack( ptr, depth, secure != 0 ); }
TRACY_API void ___tracy_emit_memory_alloc_named( const void* ptr, size_t size, int secure, const char* name ) { tracy::Profiler::MemAllocNamed( ptr, size, secure != 0, name ); }
TRACY_API void ___tracy_emit_memory_alloc_callstack_named( const void* ptr, size_t size, int depth, int secure, const char* name ) { tracy::Profiler::MemAllocCallstackNamed( ptr, size, depth, secure != 0, name ); }
TRACY_API void ___tracy_emit_memory_free_named( const void* ptr, int secure, const char* name ) { tracy::Profiler::MemFreeNamed( ptr, secure != 0, name ); }
TRACY_API void ___tracy_emit_memory_free_callstack_named( const void* ptr, int depth, int secure, const char* name ) { tracy::Profiler::MemFreeCallstackNamed( ptr, depth, secure != 0, name ); }
TRACY_API void ___tracy_emit_frame_mark( const char* name ) { tracy::Profiler::SendFrameMark( name ); }
TRACY_API void ___tracy_emit_frame_mark_start( const char* name ) { tracy::Profiler::SendFrameMark( name, tracy::QueueType::FrameMarkMsgStart ); }
TRACY_API void ___tracy_emit_frame_mark_end( const char* name ) { tracy::Profiler::SendFrameMark( name, tracy::QueueType::FrameMarkMsgEnd ); }
TRACY_API void ___tracy_emit_frame_image( const void* image, uint16_t w, uint16_t h, uint8_t offset, int flip ) { tracy::Profiler::SendFrameImage( image, w, h, offset, flip ); }
TRACY_API void ___tracy_emit_plot( const char* name, double val ) { tracy::Profiler::PlotData( name, val ); }
TRACY_API void ___tracy_emit_message( const char* txt, size_t size, int callstack ) { tracy::Profiler::Message( txt, size, callstack ); }
TRACY_API void ___tracy_emit_messageL( const char* txt, int callstack ) { tracy::Profiler::Message( txt, callstack ); }
TRACY_API void ___tracy_emit_messageC( const char* txt, size_t size, uint32_t color, int callstack ) { tracy::Profiler::MessageColor( txt, size, color, callstack ); }
TRACY_API void ___tracy_emit_messageLC( const char* txt, uint32_t color, int callstack ) { tracy::Profiler::MessageColor( txt, color, callstack ); }
TRACY_API void ___tracy_emit_message_appinfo( const char* txt, size_t size ) { tracy::Profiler::MessageAppInfo( txt, size ); }

TRACY_API uint64_t ___tracy_alloc_srcloc( uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz ) {
    return tracy::Profiler::AllocSourceLocation( line, source, sourceSz, function, functionSz );
}

TRACY_API uint64_t ___tracy_alloc_srcloc_name( uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz ) {
    return tracy::Profiler::AllocSourceLocation( line, source, sourceSz, function, functionSz, name, nameSz );
}

// thread_locals are not initialized on thread creation. At least on GNU/Linux. Instead they are
// initialized on their first ODR-use. This means that the allocator is not automagically
// initialized every time a thread is created. As thus, expose to the C API users a simple API to
// call every time they create a thread. Here we can then put all sorts of per-thread
// initialization.
TRACY_API void ___tracy_init_thread(void) {
#ifdef TRACY_DELAYED_INIT
    (void)tracy::GetProfilerThreadData();
#else
    (void)tracy::s_rpmalloc_thread_init;
#endif
}

#ifdef __cplusplus
}
#endif

#endif
