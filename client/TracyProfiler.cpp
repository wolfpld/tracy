#ifdef TRACY_ENABLE

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <windows.h>
#  include <tlhelp32.h>
#  include <inttypes.h>
#else
#  include <sys/time.h>
#endif

#ifdef __CYGWIN__
#  include <windows.h>
#endif

#ifdef _GNU_SOURCE
#  include <errno.h>
#endif

#ifdef __linux__
#  include <signal.h>
#  include <dirent.h>
#  include <sys/types.h>
#  include <sys/syscall.h>
#endif

#ifdef __APPLE__
#  include <sys/types.h>
#  include <sys/sysctl.h>
#endif

#include <atomic>
#include <assert.h>
#include <chrono>
#include <limits>
#include <memory>
#include <mutex>
#include <stdlib.h>
#include <string.h>

#include "../common/TracyAlign.hpp"
#include "../common/TracyProtocol.hpp"
#include "../common/TracySocket.hpp"
#include "../common/TracySystem.hpp"
#include "tracy_rpmalloc.hpp"
#include "TracyCallstack.hpp"
#include "TracyScoped.hpp"
#include "TracyProfiler.hpp"
#include "TracyThread.hpp"
#include "../TracyC.h"

#ifdef __APPLE__
#  define TRACY_DELAYED_INIT
#else
#  ifdef __GNUC__
#    define init_order( val ) __attribute__ ((init_priority(val)))
#  else
#    define init_order(x)
#  endif
#endif

#if defined TRACY_HW_TIMER && __ARM_ARCH >= 6 && !defined TARGET_OS_IOS
#  include <signal.h>
#  include <setjmp.h>
#endif

#if defined _WIN32 || defined __CYGWIN__
#  include <lmcons.h>
extern "C" typedef LONG (WINAPI *t_RtlGetVersion)( PRTL_OSVERSIONINFOW );
#  if _WIN32_WINNT >= _WIN32_WINNT_VISTA
#    define TRACY_USE_INIT_ONCE
#  endif
#else
#  include <unistd.h>
#  include <limits.h>
#endif
#if defined __APPLE__
#  include "TargetConditionals.h"
#endif
#if defined __linux__
#  include <sys/sysinfo.h>
#  include <sys/utsname.h>
#endif

namespace tracy
{

#ifndef TRACY_DELAYED_INIT
#  if defined TRACY_USE_INIT_ONCE
namespace
{
    BOOL CALLBACK InitOnceCallback(
        PINIT_ONCE /*initOnce*/,
        PVOID /*Parameter*/,
        PVOID* /*Context*/)
    {
        rpmalloc_initialize();
        return TRUE;
    }

    INIT_ONCE InitOnce = INIT_ONCE_STATIC_INIT;
}
#  endif //if defined TRACY_USE_INIT_ONCE

struct RPMallocInit
{
    RPMallocInit()
    {
#  if defined TRACY_USE_INIT_ONCE
        InitOnceExecuteOnce(&InitOnce, InitOnceCallback, nullptr, nullptr);
        //We must call rpmalloc_thread_initialize() explicitly here since the InitOnceCallback might
        //not be called on this thread if another thread has executed it earlier.
        rpmalloc_thread_initialize();
#  else
        rpmalloc_initialize();
#  endif //if defined TRACY_USE_INIT_ONCE
    }
};

struct RPMallocThreadInit
{
    RPMallocThreadInit()
    {
#  if defined TRACY_USE_INIT_ONCE
        InitOnceExecuteOnce(&InitOnce, InitOnceCallback, nullptr, nullptr);
#  endif //if defined TRACY_USE_INIT_ONCE
        rpmalloc_thread_initialize();
    }
};

struct InitTimeWrapper
{
    int64_t val;
};

struct ProducerWrapper
{
    tracy::moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* ptr;
};
#endif


#if defined TRACY_HW_TIMER && __ARM_ARCH >= 6 && !defined TARGET_OS_IOS
int64_t (*GetTimeImpl)();

int64_t GetTimeImplFallback()
{
#  ifdef CLOCK_MONOTONIC_RAW
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC_RAW, &ts );
    return int64_t( ts.tv_sec ) * 1000000000 + int64_t( ts.tv_nsec );
#  else
    return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
#  endif
}

int64_t GetTimeImplCntvct()
{
    int64_t t;
#  ifdef __aarch64__
    asm volatile ( "mrs %0, cntvct_el0" : "=r" (t) );
#  else
    asm volatile ( "mrrc p15, 1, %Q0, %R0, c14" : "=r" (t) );
#  endif
    return t;
}

static sigjmp_buf SigIllEnv;

static int SetupHwTimerFailed()
{
    return sigsetjmp( SigIllEnv, 1 );
}

static void SetupHwTimerSigIllHandler( int /*signum*/ )
{
    siglongjmp( SigIllEnv, 1 );
}

static int64_t SetupHwTimer()
{
    struct sigaction act, oldact;
    memset( &act, 0, sizeof( act ) );
    act.sa_handler = SetupHwTimerSigIllHandler;

    if( sigaction( SIGILL, &act, &oldact ) )
    {
        GetTimeImpl = GetTimeImplFallback;
        return Profiler::GetTime();
    }

    if( SetupHwTimerFailed() )
    {
        sigaction( SIGILL, &oldact, nullptr );
        GetTimeImpl = GetTimeImplFallback;
        return Profiler::GetTime();
    }

    GetTimeImplCntvct();

    sigaction( SIGILL, &oldact, nullptr );
    GetTimeImpl = GetTimeImplCntvct;

    // Check if cntvct is monotonic (there is faulty hw out there)
    enum { NumProbes = 32 * 1024 };
    int64_t probe[NumProbes];
    for( int j=0; j<10; j++ )
    {
        for( int i=0; i<NumProbes; i++ )
        {
            probe[i] = Profiler::GetTime();
        }
        for( int i=1; i<NumProbes; i++ )
        {
            if( probe[i] < probe[i-1] )
            {
                GetTimeImpl = GetTimeImplFallback;
                return Profiler::GetTime();
            }
        }
    }

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
#elif defined __APPLE__
    auto buf = getprogname();
    if( buf ) processName = buf;
#endif
    return processName;
}

static const char* GetHostInfo()
{
    static char buf[1024];
    auto ptr = buf;
#if defined _WIN32 || defined __CYGWIN__
#  ifdef UNICODE
    t_RtlGetVersion RtlGetVersion = (t_RtlGetVersion)GetProcAddress( GetModuleHandle( L"ntdll.dll" ), "RtlGetVersion" );
#  else
    t_RtlGetVersion RtlGetVersion = (t_RtlGetVersion)GetProcAddress( GetModuleHandle( "ntdll.dll" ), "RtlGetVersion" );
#  endif

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
    ptr += sprintf( ptr, "Compiler: MSVC %i\n", _MSC_VER );
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
#  if defined _WIN32 || defined __CYGWIN__
        __cpuidex( (int*)regs, i, 0 );
#  else
        int zero = 0;
        asm volatile ( "cpuid" : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3]) : "a" (i), "c" (zero) );
#  endif
        memcpy( modelPtr, regs, sizeof( regs ) ); modelPtr += sizeof( regs );
    }

    ptr += sprintf( ptr, "CPU: %s\n", cpuModel );
#else
    ptr += sprintf( ptr, "CPU: unknown\n" );
#endif

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
#else
    ptr += sprintf( ptr, "RAM: unknown\n" );
#endif

    return buf;
}

#ifdef _WIN32
static DWORD s_profilerThreadId = 0;
static char s_crashText[1024];

LONG WINAPI CrashFilter( PEXCEPTION_POINTERS pExp )
{
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
        const auto thread = GetThreadHandle();
        Magic magic;
        auto token = GetToken();
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::CrashReport );
        item->crashReport.time = Profiler::GetTime();
        item->crashReport.thread = thread;
        item->crashReport.text = (uint64_t)s_crashText;
        tail.store( magic + 1, std::memory_order_release );

        GetProfiler().SendCallstack( 60, thread, "KiUserExceptionDispatcher" );
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
        Magic magic;
        auto token = GetToken();
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::Crash );
        tail.store( magic + 1, std::memory_order_release );
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
        case BUS_MCEERR_AR:
            strcpy( msgPtr, "Hardware memory error consumed on a machine check; action required.\n" );
            break;
        case BUS_MCEERR_AO:
            strcpy( msgPtr, "Hardware memory error detected in process but not consumed; action optional.\n" );
            break;
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
        const auto thread = GetThreadHandle();
        Magic magic;
        auto token = GetToken();
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::CrashReport );
        item->crashReport.time = Profiler::GetTime();
        item->crashReport.thread = thread;
        item->crashReport.text = (uint64_t)s_crashText;
        tail.store( magic + 1, std::memory_order_release );

        GetProfiler().SendCallstack( 60, thread, "__kernel_rt_sigreturn" );
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
        Magic magic;
        auto token = GetToken();
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::Crash );
        tail.store( magic + 1, std::memory_order_release );
    }

    std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) );
    GetProfiler().RequestShutdown();
    while( !GetProfiler().HasShutdownFinished() ) { std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) ); };

    abort();
}
#endif


enum { QueuePrealloc = 256 * 1024 };

static Profiler* s_instance;
static Thread* s_thread;

#ifdef TRACY_DELAYED_INIT
struct ThreadNameData;
moodycamel::ConcurrentQueue<QueueItem>& GetQueue();

struct RPMallocInit { RPMallocInit() { rpmalloc_initialize(); } };
struct RPMallocThreadInit { RPMallocThreadInit() { rpmalloc_thread_initialize(); } };

void InitRPMallocThread()
{
    rpmalloc_initialize();
    rpmalloc_thread_initialize();
}

struct ProfilerData
{
    int64_t initTime = SetupHwTimer();
    RPMallocInit rpmalloc_init;
    moodycamel::ConcurrentQueue<QueueItem> queue;
    Profiler profiler;
    std::atomic<uint32_t> lockCounter = 0;
    std::atomic<uint8_t> gpuCtxCounter = 0;
#  ifdef TRACY_COLLECT_THREAD_NAMES
    std::atomic<ThreadNameData*> threadNameData = nullptr;
#endif
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
    RPMallocThreadInit rpmalloc_thread_init;
    ProducerWrapper token;
    GpuCtxWrapper gpuCtx;
#  ifdef TRACY_ON_DEMAND
    LuaZoneState luaZoneState;
#  endif
};

static ProfilerData* profilerData;

static ProfilerData& GetProfilerData()
{
    // Cannot use magic statics here.
    if( !profilerData )
    {
        profilerData = (ProfilerData*)malloc( sizeof( ProfilerData ) );
        new (profilerData) ProfilerData();
    }
    return *profilerData;
}

static ProfilerThreadData& GetProfilerThreadData()
{
    thread_local ProfilerThreadData data( GetProfilerData() );
    return data;
}

moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* GetToken() { return GetProfilerThreadData().token.ptr; }
Profiler& GetProfiler() { return GetProfilerData().profiler; }
moodycamel::ConcurrentQueue<QueueItem>& GetQueue() { return GetProfilerData().queue; }
int64_t GetInitTime() { return GetProfilerData().initTime; }
std::atomic<uint32_t>& GetLockCounter() { return GetProfilerData().lockCounter; }
std::atomic<uint8_t>& GetGpuCtxCounter() { return GetProfilerData().gpuCtxCounter; }
GpuCtxWrapper& GetGpuCtx() { return GetProfilerThreadData().gpuCtx; }

#  ifdef TRACY_COLLECT_THREAD_NAMES
std::atomic<ThreadNameData*>& GetThreadNameData() { return GetProfilerData().threadNameData; }
#  endif

#  ifdef TRACY_ON_DEMAND
LuaZoneState& GetLuaZoneState() { return GetProfilerThreadData().luaZoneState; }
#  endif

#else
void InitRPMallocThread()
{
    rpmalloc_thread_initialize();
}

// MSVC static initialization order solution. gcc/clang uses init_order() to avoid all this.

// 1a. But s_queue is needed for initialization of variables in point 2.
extern moodycamel::ConcurrentQueue<QueueItem> s_queue;

thread_local RPMallocThreadInit init_order(106) s_rpmalloc_thread_init;

// 2. If these variables would be in the .CRT$XCB section, they would be initialized only in main thread.
thread_local moodycamel::ProducerToken init_order(107) s_token_detail( s_queue );
thread_local ProducerWrapper init_order(108) s_token { s_queue.get_explicit_producer( s_token_detail ) };

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

#  ifdef TRACY_COLLECT_THREAD_NAMES
struct ThreadNameData;
static std::atomic<ThreadNameData*> init_order(104) s_threadNameDataInstance( nullptr );
std::atomic<ThreadNameData*>& s_threadNameData = s_threadNameDataInstance;
#  endif

#  ifdef TRACY_ON_DEMAND
thread_local LuaZoneState init_order(104) s_luaZoneState { 0, false };
#  endif

static Profiler init_order(105) s_profiler;

moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* GetToken() { return s_token.ptr; }
Profiler& GetProfiler() { return s_profiler; }
moodycamel::ConcurrentQueue<QueueItem>& GetQueue() { return s_queue; }
int64_t GetInitTime() { return s_initTime.val; }
std::atomic<uint32_t>& GetLockCounter() { return s_lockCounter; }
std::atomic<uint8_t>& GetGpuCtxCounter() { return s_gpuCtxCounter; }
GpuCtxWrapper& GetGpuCtx() { return s_gpuCtx; }

#  ifdef TRACY_COLLECT_THREAD_NAMES
std::atomic<ThreadNameData*>& GetThreadNameData() { return s_threadNameData; }
#  endif

#  ifdef TRACY_ON_DEMAND
LuaZoneState& GetLuaZoneState() { return s_luaZoneState; }
#  endif
#endif

// DLL exports to enable TracyClientDLL.cpp to retrieve the instances of Tracy objects and functions
#ifdef _WIN32
#  define DLL_EXPORT __declspec(dllexport)
#else
#  define DLL_EXPORT __attribute__((visibility("default")))
#endif

DLL_EXPORT void*(*get_rpmalloc())(size_t size) { return rpmalloc; }
DLL_EXPORT void(*get_rpfree())(void* ptr) { return rpfree; }
DLL_EXPORT moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer*(*get_token())() { return GetToken; }
DLL_EXPORT Profiler&(*get_profiler())() { return GetProfiler; }
DLL_EXPORT std::atomic<uint32_t>&(*get_getlockcounter())() { return GetLockCounter; }
DLL_EXPORT std::atomic<uint8_t>&(*get_getgpuctxcounter())() { return GetGpuCtxCounter; }
DLL_EXPORT GpuCtxWrapper&(*get_getgpuctx())() { return GetGpuCtx; }

#if defined TRACY_HW_TIMER && __ARM_ARCH >= 6 && !defined TARGET_OS_IOS
DLL_EXPORT int64_t(*get_GetTimeImpl())() { return GetTimeImpl; }
#endif

#ifdef TRACY_COLLECT_THREAD_NAMES
DLL_EXPORT std::atomic<ThreadNameData*>&(*get_getthreadnamedata())() { return GetThreadNameData; }
DLL_EXPORT void(*get_rpmalloc_thread_initialize())() { return rpmalloc_thread_initialize; }
DLL_EXPORT void(*get_InitRPMallocThread())() { return InitRPMallocThread; }
#endif

#ifdef TRACY_ON_DEMAND
DLL_EXPORT LuaZoneState&(*get_getluazonestate())() { return GetLuaZoneState; }
#endif

enum { BulkSize = TargetFrameSize / QueueItemSize };

Profiler::Profiler()
    : m_timeBegin( 0 )
    , m_mainThread( GetThreadHandle() )
    , m_epoch( std::chrono::duration_cast<std::chrono::seconds>( std::chrono::system_clock::now().time_since_epoch() ).count() )
    , m_shutdown( false )
    , m_shutdownManual( false )
    , m_shutdownFinished( false )
    , m_sock( nullptr )
    , m_noExit( false )
    , m_zoneId( 1 )
    , m_stream( LZ4_createStream() )
    , m_buffer( (char*)tracy_malloc( TargetFrameSize*3 ) )
    , m_bufferOffset( 0 )
    , m_bufferStart( 0 )
    , m_itemBuf( (QueueItem*)tracy_malloc( sizeof( QueueItem ) * BulkSize ) )
    , m_lz4Buf( (char*)tracy_malloc( LZ4Size + sizeof( lz4sz_t ) ) )
    , m_serialQueue( 1024*1024 )
    , m_serialDequeue( 1024*1024 )
#ifdef TRACY_ON_DEMAND
    , m_isConnected( false )
    , m_frameCount( 0 )
    , m_deferredQueue( 64*1024 )
#endif
{
    assert( !s_instance );
    s_instance = this;

#ifndef TRACY_DELAYED_INIT
#  ifdef _MSC_VER
    // 3. But these variables need to be initialized in main thread within the .CRT$XCB section. Do it here.
    s_token_detail = moodycamel::ProducerToken( s_queue );
    s_token = ProducerWrapper { s_queue.get_explicit_producer( s_token_detail ) };
#  endif
#endif

    CalibrateTimer();
    CalibrateDelay();

#ifndef TRACY_NO_EXIT
    const char* noExitEnv = getenv( "TRACY_NO_EXIT" );
    if( noExitEnv && noExitEnv[0] == '1' )
    {
        m_noExit = true;
    }
#endif

    s_thread = (Thread*)tracy_malloc( sizeof( Thread ) );
    new(s_thread) Thread( LaunchWorker, this );
    SetThreadName( s_thread->Handle(), "Tracy Profiler" );

#if defined PTW32_VERSION
    s_profilerThreadId = pthread_getw32threadid_np( s_thread->Handle() );
#elif defined __WINPTHREADS_VERSION
    s_profilerThreadId = GetThreadId( (HANDLE)pthread_gethandle( s_thread->Handle() ) );
#elif defined _MSC_VER
    s_profilerThreadId = GetThreadId( s_thread->Handle() );
#endif
#if defined _WIN32
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
    s_thread->~Thread();
    tracy_free( s_thread );

    tracy_free( m_lz4Buf );
    tracy_free( m_itemBuf );
    tracy_free( m_buffer );
    LZ4_freeStream( m_stream );

    if( m_sock )
    {
        m_sock->~Socket();
        tracy_free( m_sock );
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

    rpmalloc_thread_initialize();

    const auto procname = GetProcessName();
    const auto pnsz = std::min<size_t>( strlen( procname ), WelcomeMessageProgramNameSize - 1 );

    const auto hostinfo = GetHostInfo();
    const auto hisz = std::min<size_t>( strlen( hostinfo ), WelcomeMessageHostInfoSize - 1 );

    while( m_timeBegin.load( std::memory_order_relaxed ) == 0 ) std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );

#ifdef TRACY_ON_DEMAND
    uint8_t onDemand = 1;
#else
    uint8_t onDemand = 0;
#endif

    WelcomeMessage welcome;
    MemWrite( &welcome.timerMul, m_timerMul );
    MemWrite( &welcome.initBegin, GetInitTime() );
    MemWrite( &welcome.initEnd, m_timeBegin.load( std::memory_order_relaxed ) );
    MemWrite( &welcome.delay, m_delay );
    MemWrite( &welcome.resolution, m_resolution );
    MemWrite( &welcome.epoch, m_epoch );
    MemWrite( &welcome.onDemand, onDemand );
    memcpy( welcome.programName, procname, pnsz );
    memset( welcome.programName + pnsz, 0, WelcomeMessageProgramNameSize - pnsz );
    memcpy( welcome.hostInfo, hostinfo, hisz );
    memset( welcome.hostInfo + hisz, 0, WelcomeMessageHostInfoSize - hisz );

    moodycamel::ConsumerToken token( GetQueue() );

    ListenSocket listen;
    if( !listen.Listen( "8086", 8 ) )
    {
        for(;;)
        {
            if( ShouldExit() )
            {
                m_shutdownFinished.store( true, std::memory_order_relaxed );
                return;
            }

            ClearQueues( token );
        }
    }

    for(;;)
    {
        for(;;)
        {
#ifndef TRACY_NO_EXIT
            if( !m_noExit && ShouldExit() )
            {
                m_shutdownFinished.store( true, std::memory_order_relaxed );
                return;
            }
#endif
            m_sock = listen.Accept();
            if( m_sock ) break;
#ifndef TRACY_ON_DEMAND
            ProcessSysTime();
#endif
        }

        {
            char shibboleth[HandshakeShibbolethSize];
            auto res = m_sock->ReadRaw( shibboleth, HandshakeShibbolethSize, 2000 );
            if( !res || memcmp( shibboleth, HandshakeShibboleth, HandshakeShibbolethSize ) != 0 )
            {
                m_sock->~Socket();
                tracy_free( m_sock );
                continue;
            }

            uint32_t protocolVersion;
            res = m_sock->ReadRaw( &protocolVersion, sizeof( protocolVersion ), 2000 );
            if( !res )
            {
                m_sock->~Socket();
                tracy_free( m_sock );
                continue;
            }

            if( protocolVersion != ProtocolVersion )
            {
                HandshakeStatus status = HandshakeProtocolMismatch;
                m_sock->Send( &status, sizeof( status ) );
                m_sock->~Socket();
                tracy_free( m_sock );
                continue;
            }
        }

#ifdef TRACY_ON_DEMAND
        ClearQueues( token );
        m_isConnected.store( true, std::memory_order_relaxed );
#endif

        HandshakeStatus handshake = HandshakeWelcome;
        m_sock->Send( &handshake, sizeof( handshake ) );

        LZ4_resetStream( m_stream );
        m_sock->Send( &welcome, sizeof( welcome ) );

#ifdef TRACY_ON_DEMAND
        OnDemandPayloadMessage onDemand;
        onDemand.frames = m_frameCount.load( std::memory_order_relaxed );

        m_sock->Send( &onDemand, sizeof( onDemand ) );

        m_deferredLock.lock();
        for( auto& item : m_deferredQueue )
        {
            const auto idx = MemRead<uint8_t>( &item.hdr.idx );
            AppendData( &item, QueueDataSize[idx] );
        }
        m_deferredLock.unlock();
#endif

        int keepAlive = 0;
        for(;;)
        {
            ProcessSysTime();
            const auto status = Dequeue( token );
            const auto serialStatus = DequeueSerial();
            if( status == ConnectionLost || serialStatus == ConnectionLost )
            {
                break;
            }
            else if( status == QueueEmpty && serialStatus == QueueEmpty )
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

            while( m_sock->HasData() )
            {
                if( !HandleServerQuery() ) break;
            }
        }
        if( ShouldExit() ) break;

#ifdef TRACY_ON_DEMAND
        m_isConnected.store( false, std::memory_order_relaxed );
#endif

        m_sock->~Socket();
        tracy_free( m_sock );

#ifndef TRACY_ON_DEMAND
        // Client is no longer available here
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
                    continue;
                }

                uint32_t protocolVersion;
                res = m_sock->ReadRaw( &protocolVersion, sizeof( protocolVersion ), 1000 );
                if( !res )
                {
                    m_sock->~Socket();
                    tracy_free( m_sock );
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

    for(;;)
    {
        const auto status = Dequeue( token );
        const auto serialStatus = DequeueSerial();
        if( status == ConnectionLost || serialStatus == ConnectionLost )
        {
            break;
        }
        else if( status == QueueEmpty && serialStatus == QueueEmpty )
        {
            if( m_bufferOffset != m_bufferStart ) CommitData();
            break;
        }

        while( m_sock->HasData() )
        {
            if( !HandleServerQuery() ) break;
        }
    }

    QueueItem terminate;
    MemWrite( &terminate.hdr.type, QueueType::Terminate );
    if( !SendData( (const char*)&terminate, 1 ) )
    {
        m_shutdownFinished.store( true, std::memory_order_relaxed );
        return;
    }
    for(;;)
    {
        if( m_sock->HasData() )
        {
            while( m_sock->HasData() )
            {
                if( !HandleServerQuery() )
                {
                    if( m_bufferOffset != m_bufferStart ) CommitData();
                    m_shutdownFinished.store( true, std::memory_order_relaxed );
                    return;
                }
            }
            while( Dequeue( token ) == Success ) {}
            while( DequeueSerial() == Success ) {}
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

static void FreeAssociatedMemory( const QueueItem& item )
{
    if( item.hdr.idx >= (int)QueueType::Terminate ) return;

    uint64_t ptr;
    switch( item.hdr.type )
    {
    case QueueType::ZoneText:
    case QueueType::ZoneName:
        ptr = MemRead<uint64_t>( &item.zoneText.text );
        tracy_free( (void*)ptr );
        break;
    case QueueType::Message:
        ptr = MemRead<uint64_t>( &item.message.text );
        tracy_free( (void*)ptr );
        break;
    case QueueType::ZoneBeginAllocSrcLoc:
    case QueueType::ZoneBeginAllocSrcLocCallstack:
        ptr = MemRead<uint64_t>( &item.zoneBegin.srcloc );
        tracy_free( (void*)ptr );
        break;
    case QueueType::CallstackMemory:
        ptr = MemRead<uint64_t>( &item.callstackMemory.ptr );
        tracy_free( (void*)ptr );
        break;
    case QueueType::Callstack:
        ptr = MemRead<uint64_t>( &item.callstack.ptr );
        tracy_free( (void*)ptr );
        break;
    case QueueType::CallstackAlloc:
        ptr = MemRead<uint64_t>( &item.callstackAlloc.nativePtr );
        tracy_free( (void*)ptr );
        ptr = MemRead<uint64_t>( &item.callstackAlloc.ptr );
        tracy_free( (void*)ptr );
        break;
    default:
        assert( false );
        break;
    }
}

void Profiler::ClearQueues( moodycamel::ConsumerToken& token )
{
    for(;;)
    {
        const auto sz = GetQueue().try_dequeue_bulk( token, m_itemBuf, BulkSize );
        if( sz == 0 ) break;
        for( size_t i=0; i<sz; i++ ) FreeAssociatedMemory( m_itemBuf[i] );
    }

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
    }

    for( auto& v : m_serialDequeue ) FreeAssociatedMemory( v );
    m_serialDequeue.clear();
}

Profiler::DequeueStatus Profiler::Dequeue( moodycamel::ConsumerToken& token )
{
    const auto sz = GetQueue().try_dequeue_bulk( token, m_itemBuf, BulkSize );
    if( sz > 0 )
    {
        auto end = m_itemBuf + sz;
        auto item = m_itemBuf;
        while( item != end )
        {
            uint64_t ptr;
            const auto idx = MemRead<uint8_t>( &item->hdr.idx );
            if( idx < (int)QueueType::Terminate )
            {
                switch( (QueueType)idx )
                {
                case QueueType::ZoneText:
                case QueueType::ZoneName:
                    ptr = MemRead<uint64_t>( &item->zoneText.text );
                    SendString( ptr, (const char*)ptr, QueueType::CustomStringData );
                    tracy_free( (void*)ptr );
                    break;
                case QueueType::Message:
                    ptr = MemRead<uint64_t>( &item->message.text );
                    SendString( ptr, (const char*)ptr, QueueType::CustomStringData );
                    tracy_free( (void*)ptr );
                    break;
                case QueueType::ZoneBeginAllocSrcLoc:
                case QueueType::ZoneBeginAllocSrcLocCallstack:
                    ptr = MemRead<uint64_t>( &item->zoneBegin.srcloc );
                    SendSourceLocationPayload( ptr );
                    tracy_free( (void*)ptr );
                    break;
                case QueueType::Callstack:
                    ptr = MemRead<uint64_t>( &item->callstack.ptr );
                    SendCallstackPayload( ptr );
                    tracy_free( (void*)ptr );
                    break;
                case QueueType::CallstackAlloc:
                    ptr = MemRead<uint64_t>( &item->callstackAlloc.nativePtr );
                    CutCallstack( (void*)ptr, "lua_pcall" );
                    SendCallstackPayload( ptr );
                    tracy_free( (void*)ptr );
                    ptr = MemRead<uint64_t>( &item->callstackAlloc.ptr );
                    SendCallstackAlloc( ptr );
                    tracy_free( (void*)ptr );
                    break;
                default:
                    assert( false );
                    break;
                }
            }
            if( !AppendData( item, QueueDataSize[idx] ) ) return ConnectionLost;
            item++;
        }
    }
    else
    {
        return QueueEmpty;
    }
    return Success;
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
        m_serialQueue.swap( m_serialDequeue );
        if( lockHeld )
        {
            m_serialLock.unlock();
        }
    }

    const auto sz = m_serialDequeue.size();
    if( sz > 0 )
    {
        auto item = m_serialDequeue.data();
        auto end = item + sz;
        while( item != end )
        {
            uint64_t ptr;
            const auto idx = MemRead<uint8_t>( &item->hdr.idx );
            if( idx < (int)QueueType::Terminate )
            {
                switch( (QueueType)idx )
                {
                case QueueType::CallstackMemory:
                    ptr = MemRead<uint64_t>( &item->callstackMemory.ptr );
                    SendCallstackPayload( ptr );
                    tracy_free( (void*)ptr );
                    break;
                default:
                    assert( false );
                    break;
                }
            }
            if( !AppendData( item, QueueDataSize[idx] ) ) return ConnectionLost;
            item++;
        }
        m_serialDequeue.clear();
    }
    else
    {
        return QueueEmpty;
    }
    return Success;
}

bool Profiler::AppendData( const void* data, size_t len )
{
    const auto ret = NeedDataSize( len );
    AppendDataUnsafe( data, len );
    return ret;
}

bool Profiler::CommitData()
{
    bool ret = SendData( m_buffer + m_bufferStart, m_bufferOffset - m_bufferStart );
    if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;
    m_bufferStart = m_bufferOffset;
    return ret;
}

bool Profiler::NeedDataSize( size_t len )
{
    bool ret = true;
    if( m_bufferOffset - m_bufferStart + len > TargetFrameSize )
    {
        ret = CommitData();
    }
    return ret;
}

bool Profiler::SendData( const char* data, size_t len )
{
    const lz4sz_t lz4sz = LZ4_compress_fast_continue( m_stream, data, m_lz4Buf + sizeof( lz4sz_t ), (int)len, LZ4Size, 1 );
    memcpy( m_lz4Buf, &lz4sz, sizeof( lz4sz ) );
    return m_sock->Send( m_lz4Buf, lz4sz + sizeof( lz4sz_t ) ) != -1;
}

void Profiler::SendString( uint64_t str, const char* ptr, QueueType type )
{
    assert( type == QueueType::StringData || type == QueueType::ThreadName || type == QueueType::CustomStringData || type == QueueType::PlotName || type == QueueType::FrameName );

    QueueItem item;
    MemWrite( &item.hdr.type, type );
    MemWrite( &item.stringTransfer.ptr, str );

    auto len = strlen( ptr );
    assert( len <= std::numeric_limits<uint16_t>::max() );
    auto l16 = uint16_t( len );

    NeedDataSize( QueueDataSize[(int)type] + sizeof( l16 ) + l16 );

    AppendDataUnsafe( &item, QueueDataSize[(int)type] );
    AppendDataUnsafe( &l16, sizeof( l16 ) );
    AppendDataUnsafe( ptr, l16 );
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

    const auto len = *((uint32_t*)ptr);
    assert( len <= std::numeric_limits<uint16_t>::max() );
    assert( len > 4 );
    const auto l16 = uint16_t( len - 4 );

    NeedDataSize( QueueDataSize[(int)QueueType::SourceLocationPayload] + sizeof( l16 ) + l16 );

    AppendDataUnsafe( &item, QueueDataSize[(int)QueueType::SourceLocationPayload] );
    AppendDataUnsafe( &l16, sizeof( l16 ) );
    AppendDataUnsafe( ptr + 4, l16 );
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

void Profiler::SendCallstackAlloc( uint64_t _ptr )
{
    auto ptr = (const char*)_ptr;

    QueueItem item;
    MemWrite( &item.hdr.type, QueueType::CallstackAllocPayload );
    MemWrite( &item.stringTransfer.ptr, _ptr );

    const auto len = *((uint32_t*)ptr);
    assert( len <= std::numeric_limits<uint16_t>::max() );
    const auto l16 = uint16_t( len );

    NeedDataSize( QueueDataSize[(int)QueueType::CallstackAllocPayload] + sizeof( l16 ) + l16 );

    AppendDataUnsafe( &item, QueueDataSize[(int)QueueType::CallstackAllocPayload] );
    AppendDataUnsafe( &l16, sizeof( l16 ) );
    AppendDataUnsafe( ptr + 4, l16 );
}

void Profiler::SendCallstackFrame( uint64_t ptr )
{
#ifdef TRACY_HAS_CALLSTACK
    const auto frameData = DecodeCallstackPtr( ptr );

    {
        QueueItem item;
        MemWrite( &item.hdr.type, QueueType::CallstackFrameSize );
        MemWrite( &item.callstackFrameSize.ptr, ptr );
        MemWrite( &item.callstackFrameSize.size, frameData.size );

        AppendData( &item, QueueDataSize[(int)QueueType::CallstackFrameSize] );
    }

    for( uint8_t i=0; i<frameData.size; i++ )
    {
        const auto& frame = frameData.data[i];

        SendString( uint64_t( frame.name ), frame.name, QueueType::CustomStringData );
        SendString( uint64_t( frame.file ), frame.file, QueueType::CustomStringData );

        QueueItem item;
        MemWrite( &item.hdr.type, QueueType::CallstackFrame );
        MemWrite( &item.callstackFrame.name, (uint64_t)frame.name );
        MemWrite( &item.callstackFrame.file, (uint64_t)frame.file );
        MemWrite( &item.callstackFrame.line, frame.line );

        AppendData( &item, QueueDataSize[(int)QueueType::CallstackFrame] );

        tracy_free( (void*)frame.name );
        tracy_free( (void*)frame.file );
    }
#endif
}


static bool DontExit() { return false; }

bool Profiler::HandleServerQuery()
{
    uint8_t type;
    if( !m_sock->Read( &type, sizeof( type ), 10, DontExit ) ) return false;

    uint64_t ptr;
    if( !m_sock->Read( &ptr, sizeof( ptr ), 10, DontExit ) ) return false;

    switch( type )
    {
    case ServerQueryString:
        SendString( ptr, (const char*)ptr, QueueType::StringData );
        break;
    case ServerQueryThreadString:
        if( ptr == m_mainThread )
        {
            SendString( ptr, "Main thread", QueueType::ThreadName );
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
    default:
        assert( false );
        break;
    }

    return true;
}

void Profiler::CalibrateTimer()
{
#ifdef TRACY_HW_TIMER
#  if __ARM_ARCH >= 6 && !defined TARGET_OS_IOS
    if( GetTimeImpl == GetTimeImplFallback )
    {
        m_timerMul = 1.;
        return;
    }
#  endif

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

class FakeZone
{
public:
    FakeZone( const SourceLocationData* srcloc ) : m_id( (uint64_t)srcloc ) {}
    ~FakeZone() {}

private:
    volatile uint64_t m_id;
};

void Profiler::CalibrateDelay()
{
    enum { Iterations = 50000 };
    enum { Events = Iterations * 2 };   // start + end
    static_assert( Events * 2 < QueuePrealloc, "Delay calibration loop will allocate memory in queue" );

    moodycamel::ProducerToken ptoken_detail( GetQueue() );
    moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* ptoken = GetQueue().get_explicit_producer( ptoken_detail );
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocationData __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 };
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::ZoneBegin );
            MemWrite( &item->zoneBegin.thread, GetThreadHandle() );
#ifdef TRACY_RDTSCP_OPT
            MemWrite( &item->zoneBegin.time, Profiler::GetTime( item->zoneBegin.cpu ) );
#else
            uint32_t cpu;
            MemWrite( &item->zoneBegin.time, Profiler::GetTime( cpu ) );
            MemWrite( &item->zoneBegin.cpu, cpu );
#endif
            MemWrite( &item->zoneBegin.srcloc, (uint64_t)&__tracy_source_location );
            tail.store( magic + 1, std::memory_order_release );
        }
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::ZoneEnd );
            MemWrite( &item->zoneEnd.thread, uint64_t( 0 ) );
#ifdef TRACY_RDTSCP_OPT
            MemWrite( &item->zoneEnd.time, GetTime( item->zoneEnd.cpu ) );
#else
            uint32_t cpu;
            MemWrite( &item->zoneEnd.time, GetTime( cpu ) );
            MemWrite( &item->zoneEnd.cpu, cpu );
#endif
            tail.store( magic + 1, std::memory_order_release );
        }
    }
    const auto f0 = GetTime();
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocationData __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 };
        FakeZone ___tracy_scoped_zone( &__tracy_source_location );
    }
    const auto t0 = GetTime();
    for( int i=0; i<Iterations; i++ )
    {
        static const tracy::SourceLocationData __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 };
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::ZoneBegin );
            MemWrite( &item->zoneBegin.thread, GetThreadHandle() );
#ifdef TRACY_RDTSCP_OPT
            MemWrite( &item->zoneBegin.time, Profiler::GetTime( item->zoneBegin.cpu ) );
#else
            uint32_t cpu;
            MemWrite( &item->zoneBegin.time, Profiler::GetTime( cpu ) );
            MemWrite( &item->zoneBegin.cpu, cpu );
#endif
            MemWrite( &item->zoneBegin.srcloc, (uint64_t)&__tracy_source_location );
            tail.store( magic + 1, std::memory_order_release );
        }
        {
            Magic magic;
            auto& tail = ptoken->get_tail_index();
            auto item = ptoken->enqueue_begin<moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::ZoneEnd );
            MemWrite( &item->zoneEnd.thread, uint64_t( 0 ) );
#ifdef TRACY_RDTSCP_OPT
            MemWrite( &item->zoneEnd.time, GetTime( item->zoneEnd.cpu ) );
#else
            uint32_t cpu;
            MemWrite( &item->zoneEnd.time, GetTime( cpu ) );
            MemWrite( &item->zoneEnd.cpu, cpu );
#endif
            tail.store( magic + 1, std::memory_order_release );
        }
    }
    const auto t1 = GetTime();
    const auto dt = t1 - t0;
    const auto df = t0 - f0;
    m_delay = ( dt - df ) / Events;

    auto mindiff = std::numeric_limits<int64_t>::max();
    for( int i=0; i<Iterations * 10; i++ )
    {
        const auto t0i = GetTime();
        const auto t1i = GetTime();
        const auto dti = t1i - t0i;
        if( dti > 0 && dti < mindiff ) mindiff = dti;
    }

    m_resolution = mindiff;

    enum { Bulk = 1000 };
    moodycamel::ConsumerToken token( GetQueue() );
    int left = Events * 2;
    QueueItem item[Bulk];
    while( left != 0 )
    {
        const auto sz = GetQueue().try_dequeue_bulk( token, item, std::min( left, (int)Bulk ) );
        assert( sz > 0 );
        left -= (int)sz;
    }
}

void Profiler::SendCallstack( int depth, uint64_t thread, const char* skipBefore )
{
#ifdef TRACY_HAS_CALLSTACK
    auto ptr = Callstack( depth );
    CutCallstack( ptr, skipBefore );

    Magic magic;
    auto token = GetToken();
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
    MemWrite( &item->hdr.type, QueueType::Callstack );
    MemWrite( &item->callstack.ptr, ptr );
    MemWrite( &item->callstack.thread, thread );
    tail.store( magic + 1, std::memory_order_release );
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
    auto t = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    if( t - m_sysTimeLast > 100000000 )    // 100 ms
    {
        auto sysTime = m_sysTime.Get();
        if( sysTime >= 0 )
        {
            m_sysTimeLast = t;

            Magic magic;
            auto token = GetToken();
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::SysTimeReport );
            MemWrite( &item->sysTime.time, GetTime() );
            MemWrite( &item->sysTime.sysTime, sysTime );
            tail.store( magic + 1, std::memory_order_release );
        }
    }
}
#endif

}

#ifdef __cplusplus
extern "C" {
#endif

TracyCZoneCtx ___tracy_emit_zone_begin( const struct ___tracy_source_location_data* srcloc, int active )
{
    ___tracy_c_zone_context ctx;
#ifdef TRACY_ON_DEMAND
    ctx.active = active && tracy::GetProfiler().IsConnected();
#else
    ctx.active = active;
#endif
    if( !ctx.active ) return ctx;
    const auto thread = tracy::GetThreadHandle();
    const auto id = tracy::GetProfiler().GetNextZoneId();
    ctx.id = id;

    tracy::Magic magic;
    auto token = tracy::GetToken();
    auto& tail = token->get_tail_index();
#ifndef TRACY_NO_VERIFY
    {
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        tracy::MemWrite( &item->hdr.type, tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.thread, thread );
        tracy::MemWrite( &item->zoneValidation.id, id );
        tail.store( magic + 1, std::memory_order_release );
    }
#endif
    {
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        tracy::MemWrite( &item->hdr.type, tracy::QueueType::ZoneBegin );
#ifdef TRACY_RDTSCP_OPT
        tracy::MemWrite( &item->zoneBegin.time, tracy::Profiler::GetTime( item->zoneBegin.cpu ) );
#else
        uint32_t cpu;
        tracy::MemWrite( &item->zoneBegin.time, tracy::Profiler::GetTime( cpu ) );
        tracy::MemWrite( &item->zoneBegin.cpu, cpu );
#endif
        tracy::MemWrite( &item->zoneBegin.thread, thread );
        tracy::MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        tail.store( magic + 1, std::memory_order_release );
    }
    return ctx;
}

TracyCZoneCtx ___tracy_emit_zone_begin_callstack( const struct ___tracy_source_location_data* srcloc, int depth, int active )
{
    ___tracy_c_zone_context ctx;
#ifdef TRACY_ON_DEMAND
    ctx.active = active && tracy::GetProfiler().IsConnected();
#else
    ctx.active = active;
#endif
    if( !ctx.active ) return ctx;
    const auto thread = tracy::GetThreadHandle();
    const auto id = tracy::GetProfiler().GetNextZoneId();
    ctx.id = id;

    tracy::Magic magic;
    auto token = tracy::GetToken();
    auto& tail = token->get_tail_index();
#ifndef TRACY_NO_VERIFY
    {
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        tracy::MemWrite( &item->hdr.type, tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.thread, thread );
        tracy::MemWrite( &item->zoneValidation.id, id );
        tail.store( magic + 1, std::memory_order_release );
    }
#endif
    {
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        tracy::MemWrite( &item->hdr.type, tracy::QueueType::ZoneBeginCallstack );
#ifdef TRACY_RDTSCP_OPT
        tracy::MemWrite( &item->zoneBegin.time, tracy::Profiler::GetTime( item->zoneBegin.cpu ) );
#else
        uint32_t cpu;
        tracy::MemWrite( &item->zoneBegin.time, tracy::Profiler::GetTime( cpu ) );
        tracy::MemWrite( &item->zoneBegin.cpu, cpu );
#endif
        tracy::MemWrite( &item->zoneBegin.thread, thread );
        tracy::MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy::GetProfiler().SendCallstack( depth, thread );
    return ctx;
}

void ___tracy_emit_zone_end( TracyCZoneCtx ctx )
{
    if( !ctx.active ) return;
    const auto thread = tracy::GetThreadHandle();
    tracy::Magic magic;
    auto token = tracy::GetToken();
    auto& tail = token->get_tail_index();
#ifndef TRACY_NO_VERIFY
    {
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        tracy::MemWrite( &item->hdr.type, tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.thread, thread );
        tracy::MemWrite( &item->zoneValidation.id, ctx.id );
        tail.store( magic + 1, std::memory_order_release );
    }
#endif
    {
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        tracy::MemWrite( &item->hdr.type, tracy::QueueType::ZoneEnd );
#ifdef TRACY_RDTSCP_OPT
        tracy::MemWrite( &item->zoneEnd.time, tracy::Profiler::GetTime( item->zoneEnd.cpu ) );
#else
        uint32_t cpu;
        tracy::MemWrite( &item->zoneEnd.time, tracy::Profiler::GetTime( cpu ) );
        tracy::MemWrite( &item->zoneEnd.cpu, cpu );
#endif
        tracy::MemWrite( &item->zoneEnd.thread, thread );
        tail.store( magic + 1, std::memory_order_release );
    }
}

void ___tracy_emit_zone_text( TracyCZoneCtx ctx, const char* txt, size_t size )
{
    if( !ctx.active ) return;
    const auto thread = tracy::GetThreadHandle();
    tracy::Magic magic;
    auto token = tracy::GetToken();
    auto ptr = (char*)tracy::tracy_malloc( size+1 );
    memcpy( ptr, txt, size );
    ptr[size] = '\0';
    auto& tail = token->get_tail_index();
#ifndef TRACY_NO_VERIFY
    {
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        tracy::MemWrite( &item->hdr.type, tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.thread, thread );
        tracy::MemWrite( &item->zoneValidation.id, ctx.id );
        tail.store( magic + 1, std::memory_order_release );
    }
#endif
    {
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        tracy::MemWrite( &item->hdr.type, tracy::QueueType::ZoneText );
        tracy::MemWrite( &item->zoneText.thread, thread );
        tracy::MemWrite( &item->zoneText.text, (uint64_t)ptr );
        tail.store( magic + 1, std::memory_order_release );
    }
}

void ___tracy_emit_zone_name( TracyCZoneCtx ctx, const char* txt, size_t size )
{
    if( !ctx.active ) return;
    const auto thread = tracy::GetThreadHandle();
    tracy::Magic magic;
    auto token = tracy::GetToken();
    auto ptr = (char*)tracy::tracy_malloc( size+1 );
    memcpy( ptr, txt, size );
    ptr[size] = '\0';
    auto& tail = token->get_tail_index();
#ifndef TRACY_NO_VERIFY
    {
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        tracy::MemWrite( &item->hdr.type, tracy::QueueType::ZoneValidation );
        tracy::MemWrite( &item->zoneValidation.thread, thread );
        tracy::MemWrite( &item->zoneValidation.id, ctx.id );
        tail.store( magic + 1, std::memory_order_release );
    }
#endif
    {
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        tracy::MemWrite( &item->hdr.type, tracy::QueueType::ZoneName );
        tracy::MemWrite( &item->zoneText.thread, thread );
        tracy::MemWrite( &item->zoneText.text, (uint64_t)ptr );
        tail.store( magic + 1, std::memory_order_release );
    }
}

#ifdef __cplusplus
}
#endif

#endif
