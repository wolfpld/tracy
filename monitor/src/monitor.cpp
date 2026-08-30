#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../public/tracy/Tracy.hpp"
#include "../public/common/TracyVersion.hpp"
#include "../public/client/TracyCallstack.hpp"
#include "GitRef.hpp"

// The monitor is only meaningful with the client's full sampling +
// symbolication stack. These configurations would either fail to build
// (TRACY_NO_CALLSTACK: the external-target API lives in the callstack
// code) or silently produce an empty capture (IsSystemTracingFailed()
// cannot see them), so reject them here rather than in the client.
#if defined TRACY_NO_CALLSTACK
#  error "tracy-monitor requires callstack support: TRACY_NO_CALLSTACK is not supported"
#endif
#if defined TRACY_NO_SYSTEM_TRACING
#  error "tracy-monitor requires system tracing: TRACY_NO_SYSTEM_TRACING is not supported"
#endif
#if defined TRACY_NO_SAMPLING
#  error "tracy-monitor requires callstack sampling: TRACY_NO_SAMPLING is not supported"
#endif
#if defined TRACY_SAMPLING_PROFILER_MANUAL_START
#  error "tracy-monitor starts sampling itself via StartupProfiler(): TRACY_SAMPLING_PROFILER_MANUAL_START is not supported"
#endif

static volatile sig_atomic_t s_shouldQuit = 0;
static pid_t s_targetPid = 0;
static bool s_isForked = false;

static void SignalHandler( int sig )
{
    s_shouldQuit = 1;
    if( s_isForked && s_targetPid != 0 )
    {
        // We launched the target under ptrace, so forward the signal to wake
        // a blocking waitpid and let the child exit. kill() is async-signal-safe.
        kill( s_targetPid, SIGINT );
    }
}

// kill( pid, 0 ) succeeds even for zombies, so liveness also checks the
// /proc state: a zombie is dead - nothing left to sample, and in attach
// mode we are not the parent, so we can neither reap it nor learn its exit.
static bool ProcessIsAlive( pid_t pid )
{
    if( kill( pid, 0 ) != 0 ) return false;
    char path[32];
    snprintf( path, sizeof( path ), "/proc/%d/stat", (int)pid );
    FILE* f = fopen( path, "r" );
    if( !f ) return false;
    char buf[512];
    const size_t n = fread( buf, 1, sizeof( buf ) - 1, f );
    fclose( f );
    buf[n] = 0;
    // the state char follows the last ')' (comm may contain spaces/parens)
    const char* state = strrchr( buf, ')' );
    return state && state[1] == ' ' && state[2] != 'Z' && state[2] != '\0';
}

static const char* GetTraceFsPath()
{
    static char path[ 4096 ];
    static char debugPath[ 4096 ];
    bool haveDebug = false;
    FILE* f = fopen( "/proc/mounts", "r" );
    if( !f ) return nullptr;
    char line[ 4096 ];
    while( fgets( line, sizeof( line ), f ) )
    {
        char dir[ 4096 ];
        char type[ 64 ];
        if( sscanf( line, "%*s %4095s %63s", dir, type ) != 2 ) continue;
        if( strcmp( type, "tracefs" ) == 0 )
        {
            snprintf( path, sizeof( path ), "%s", dir );
            fclose( f );
            return path;
        }
        if( !haveDebug && strcmp( type, "debugfs" ) == 0 )
        {
            snprintf( debugPath, sizeof( debugPath ), "%s/tracing", dir );
            haveDebug = true;
        }
    }
    fclose( f );
    if( haveDebug )
    {
        snprintf( path, sizeof( path ), "%s", debugPath );
        return path;
    }
    return nullptr;
}

enum class TracepointStatus { Open, NoTraceFs, IdNotReadable, OpenDenied };

// open a system-wide per-CPU tracepoint (the client's sched/vblank shape);
// report the failure distinctly - tracefs readability (root) and the perf open (paranoid/CAP_PERFMON) are independent gates.
static TracepointStatus CheckSystemWideTracepoint( const char* eventPath )
{
    const char* traceFs = GetTraceFsPath();
    if( !traceFs ) return TracepointStatus::NoTraceFs;

    char path[512];
    snprintf( path, sizeof( path ), "%s%s/id", traceFs, eventPath );
    FILE* f = fopen( path, "r" );
    if( !f ) return TracepointStatus::IdNotReadable;
    int id = -1;
    if( fscanf( f, "%d", &id ) != 1 ) id = -1;
    fclose( f );
    if( id < 0 ) return TracepointStatus::IdNotReadable;

    perf_event_attr pe = {};
    pe.type = PERF_TYPE_TRACEPOINT;
    pe.size = sizeof( pe );
    pe.config = (uint64_t)id;
    pe.sample_period = 1;
    pe.sample_type = PERF_SAMPLE_TIME | PERF_SAMPLE_RAW;
    pe.disabled = 1;
    pe.inherit = 1;

    const long fd = syscall( __NR_perf_event_open, &pe, -1, 0, -1, 0 );
    if( fd < 0 ) return TracepointStatus::OpenDenied;
    close( (int)fd );
    return TracepointStatus::Open;
}

// Power plots read RAPL energy counters (the client scans the same tree).
static bool CanReadRapl()
{
    const char* base = "/sys/devices/virtual/powercap/intel-rapl";
    DIR* dir = opendir( base );
    if( !dir ) return false;
    struct dirent* ent;
    bool ok = false;
    while( ( ent = readdir( dir ) ) )
    {
        if( ent->d_type != DT_DIR || strncmp( ent->d_name, "intel-rapl:", 11 ) != 0 ) continue;
        char path[512];
        snprintf( path, sizeof( path ), "%s/%s/energy_uj", base, ent->d_name );
        FILE* f = fopen( path, "r" );
        if( f )
        {
            fclose( f );
            ok = true;
            break;
        }
    }
    closedir( dir );
    return ok;
}

// verify the per-CPU pid-filtered event mechanism the client relies on:
// perf_event_open(attr, target, cpu) with a direct mmap of the event's ring
// (the normal client's own topology); exclude_kernel=1 so it works at any
// paranoid level.
static bool PreflightOutputMechanism( pid_t pid )
{
    perf_event_attr pe = {};
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof( pe );
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    pe.sample_freq = 100;
    pe.freq = 1;
    pe.disabled = 1;
    pe.inherit = 1;
    pe.exclude_kernel = 1;
    pe.exclude_callchain_kernel = 1;

    const long fd = syscall( __NR_perf_event_open, &pe, pid, 0, -1, 0 );
    if( fd < 0 )
    {
        fprintf( stderr, "Warning: preflight per-CPU event open failed: %s\n", strerror( errno ) );
        return false;
    }
    const size_t mapSize = 64 * 1024 + 4096;
    void* map = mmap( nullptr, mapSize, PROT_READ | PROT_WRITE, MAP_SHARED, (int)fd, 0 );
    bool ok = map != MAP_FAILED;
    if( !ok ) fprintf( stderr, "Warning: preflight ring mmap refused: %s (kernel ABI mismatch?)\n", strerror( errno ) );
    if( map != MAP_FAILED ) munmap( map, mapSize );
    close( (int)fd );
    return ok;
}

// probe whether the client's per-thread hardware PMU counters can open at all
// (the client drops them silently on failure, losing the IPC/cache/branch plots); informational only.
static bool ProbeHwCounters( pid_t pid, int& errOut )
{
    perf_event_attr pe = {};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof( pe );
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.disabled = 1;
    pe.precise_ip = 3;
    long fd = syscall( __NR_perf_event_open, &pe, pid, -1, -1, 0 );
    while( fd < 0 && pe.precise_ip > 0 )
    {
        pe.precise_ip--;
        fd = syscall( __NR_perf_event_open, &pe, pid, -1, -1, 0 );
    }
    if( fd < 0 && ( errno == EACCES || errno == EPERM ) )
    {
        pe.exclude_kernel = 1;
        fd = syscall( __NR_perf_event_open, &pe, pid, -1, -1, 0 );
    }
    if( fd >= 0 )
    {
        close( (int)fd );
        return true;
    }
    errOut = errno;
    return false;
}

// mirror the client's exact external perf_event_open (SysTraceStart/OpenSampleEvent):
// a per-CPU event with a pid filter on the target (direct ring mmap), plus an
// informational hardware PMU probe. Failing fast here yields an accurate
// capability report instead of starting the profiler with no samples.
static bool PreflightSamplingEvent( pid_t pid, bool& kernelFrames, bool& hwStats, int& hwErrno )
{
    perf_event_attr pe = {};
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof( pe );
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CALLCHAIN;
    pe.sample_freq = 1000;
    pe.freq = 1;
    pe.disabled = 1;
    pe.inherit = 1;

    long dataFd = syscall( __NR_perf_event_open, &pe, pid, 0, -1, 0 );
    if( dataFd < 0 )
    {
        const int err = errno;
        if( err == ESRCH )
        {
            fprintf( stderr, "Target process %d no longer exists.\n", (int)pid );
            return false;
        }
        if( err == EACCES || err == EPERM )
        {
            // no kernel access: retry user-space-only, in both the event and the callchain
            pe.exclude_kernel = 1;
            pe.exclude_callchain_kernel = 1;
            dataFd = syscall( __NR_perf_event_open, &pe, pid, 0, -1, 0 );
            if( dataFd >= 0 )
            {
                close( (int)dataFd );
                kernelFrames = false;
            }
        }
        else
        {
            // any other error (EINVAL, ENOSYS under seccomp, exhaustion): the client's same
            // event shape would fail identically and produce an empty capture, so fail here.
            fprintf( stderr, "Cannot open perf events for pid %d: %s\n", (int)pid, strerror( err ) );
            return false;
        }
    }
    else
    {
        close( (int)dataFd );
        kernelFrames = true;
    }

    if( dataFd < 0 )
    {
        fprintf( stderr, "Cannot open perf events for pid %d: %s\n", (int)pid, strerror( errno ) );
        fprintf( stderr, "Profiling another process requires one of:\n" );
        fprintf( stderr, "  - running as root (or CAP_PERFMON + CAP_SYS_PTRACE), or\n" );
        fprintf( stderr, "  - /proc/sys/kernel/perf_event_paranoid <= 1 for kernel frames,\n" );
        fprintf( stderr, "    <= -1 for system-wide events (context switches / per-thread\n" );
        fprintf( stderr, "    CPU / wait stacks), or\n" );
        fprintf( stderr, "  - in attach mode: the target must belong to the same user\n" );
        fprintf( stderr, "    (uid and gid) and be dumpable, or the monitor must hold\n" );
        fprintf( stderr, "    CAP_SYS_PTRACE (yama ptrace_scope does not apply: sampling\n" );
        fprintf( stderr, "    uses ptrace READ access, and the monitor never attaches).\n" );
        return false;
    }

    if( !PreflightOutputMechanism( pid ) )
    {
        fprintf( stderr, "Per-CPU sample rings are unavailable on this kernel; external sampling will not work.\n" );
        return false;
    }
    hwStats = ProbeHwCounters( pid, hwErrno );
    return true;
}

static const char* FormatHz( int hz )
{
    static char buf[32];
    if( hz >= 1000 && hz % 1000 == 0 )
    {
        snprintf( buf, sizeof( buf ), "%d kHz", hz / 1000 );
    }
    else
    {
        snprintf( buf, sizeof( buf ), "%d Hz", hz );
    }
    return buf;
}

static int EffectiveSamplingHz()
{
    const char* env = getenv( "TRACY_SAMPLING_HZ" );
    int hz = 10000; // client default on Linux
    if( env )
    {
        const int parsed = atoi( env );
        if( parsed > 0 ) hz = ( parsed > 1000000 ) ? 1000000 : parsed;
    }
    // mirror the client's clamp: the kernel caps the rate at perf_event_max_sample_rate
    FILE* f = fopen( "/proc/sys/kernel/perf_event_max_sample_rate", "r" );
    if( f )
    {
        int sysMax = 0;
        if( fscanf( f, "%d", &sysMax ) == 1 && sysMax > 0 && sysMax < hz ) hz = sysMax;
        fclose( f );
    }
    return hz;
}

static int EffectivePort()
{
    const char* env = getenv( "TRACY_PORT" );
    if( env )
    {
        const int port = atoi( env );
        if( port > 0 && port <= 65535 ) return port;
    }
    return 8086;
}

static const char* TracepointReason( TracepointStatus status )
{
    switch( status )
    {
    case TracepointStatus::NoTraceFs: return "tracefs is not readable — running as root is required";
    case TracepointStatus::IdNotReadable: return "the event id is not readable — running as root is required";
    case TracepointStatus::OpenDenied: return "system-wide events are denied — needs perf_event_paranoid <= -1 or CAP_PERFMON";
    default: return nullptr;
    }
}

static void PrintStartupReport( bool kernelFrames, bool hwStats, int hwErrno )
{
    const TracepointStatus ctxSwitches = CheckSystemWideTracepoint( "/events/sched/sched_switch" );
    const TracepointStatus vsync = CheckSystemWideTracepoint( "/events/drm/drm_vblank_event" );
    const bool power = CanReadRapl();

    printf( "tracy-monitor %i.%i.%i / %s\n", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
    printf( "Profiling '%s' (pid %d) on port %d\n", tracy::GetExternalTargetName(), (int)tracy::GetExternalTargetPid(), EffectivePort() );
    printf( "  sampling:                      %s, %s callchain — leaf-only stacks for -fomit-frame-pointer targets\n", FormatHz( EffectiveSamplingHz() ), kernelFrames ? "kernel" : "user-space" );
    printf( "  kernel frames:                 %s\n", kernelFrames ? "yes" : "no (kernel sampling denied — perf_event_paranoid > 1 without CAP_PERFMON)" );
    if( hwStats )
    {
        printf( "  hardware sampling statistics:  yes\n" );
    }
    else
    {
        printf( "  hardware sampling statistics:  no (PMU counters unavailable: %s)\n", strerror( hwErrno ) );
    }
    if( ctxSwitches == TracepointStatus::Open )
    {
        printf( "  ctx switches / per-thread CPU: yes\n" );
    }
    else
    {
        printf( "  ctx switches / per-thread CPU: no (%s)\n", TracepointReason( ctxSwitches ) );
    }
    printf( "  power (RAPL):                  %s\n", power ? "yes" : "no (needs read access to /sys/devices/virtual/powercap/intel-rapl)" );
    if( vsync == TracepointStatus::Open )
    {
        printf( "  vsync:                         yes\n" );
    }
    else
    {
        printf( "  vsync:                         no (%s)\n", TracepointReason( vsync ) );
    }
    printf( "\n" );
    printf( "Open the Tracy profiler and connect to this host:port (or it will auto-discover).\n" );
    fflush( stdout );
}

static void PrintUsage( const char* progName )
{
    printf( "tracy-monitor %i.%i.%i / %s\n\n", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
    printf( "Usage: %s [OPTIONS] program [arguments...]\n", progName );
    printf( "       %s [OPTIONS] -p PID\n", progName );
    printf( "\n" );
    printf( "Options:\n" );
    printf( "  -p PID        Attach to existing process (PID)\n" );
    printf( "  -n NAME       Attach to existing process by name\n" );
    printf( "  --hz N        Sampling frequency in Hz (default 10000, range 1..1000000)\n" );
    printf( "  --port N      Listen port for Tracy servers (default 8086)\n" );
    printf( "  -h            Show this help message\n" );
    printf( "\n" );
    printf( "Examples:\n" );
    printf( "  %s ./my_program arg1 arg2\n", progName );
    printf( "  %s -p 1234\n", progName );
    printf( "  %s -n my_program\n", progName );
    printf( "\n" );
    printf( "The monitor captures sampling profiling data from an external process\n" );
    printf( "and streams it to a Tracy server for visualization.\n" );
    printf( "\n" );
    printf( "In launch mode, the target program is started under ptrace control to\n" );
    printf( "ensure profiling begins before the first instruction executes.\n" );
    printf( "\n" );
    printf( "In attach mode (-p), the target must already be running.\n" );
}

static int FindPidsByComm( const char* name, pid_t* outPids, int maxPids )
{
    int count = 0;
    DIR* proc = opendir( "/proc" );
    if( !proc ) return 0;
    struct dirent* ent;
    while( ( ent = readdir( proc ) ) )
    {
        if( ent->d_name[0] < '0' || ent->d_name[0] > '9' ) continue;
        char path[64];
        snprintf( path, sizeof( path ), "/proc/%s/comm", ent->d_name );
        FILE* f = fopen( path, "r" );
        if( !f ) continue;
        char comm[32] = {};
        if( fgets( comm, sizeof( comm ), f ) )
        {
            size_t len = strlen( comm );
            while( len > 0 && ( comm[len-1] == '\n' || comm[len-1] == '\r' ) ) comm[--len] = '\0';
            if( strcmp( comm, name ) == 0 && count < maxPids )
            {
                // gate on /proc/<pid>/exe: zombies keep a comm but have no executable to map
                char exe[256] = {};
                snprintf( path, sizeof( path ), "/proc/%s/exe", ent->d_name );
                if( readlink( path, exe, sizeof( exe ) - 1 ) >= 0 )
                {
                    outPids[count++] = (pid_t)atoi( ent->d_name );
                }
            }
        }
        fclose( f );
    }
    closedir( proc );
    return count;
}

static bool VerifyClientListening()
{
    for( int i = 0; i < 40; i++ )
    {
        if( tracy::IsDataPortListening() ) return true;
        usleep( 125000 );
    }
    return false;
}
static int RunAttached( pid_t pid )
{
    if( kill( pid, 0 ) != 0 )
    {
        fprintf( stderr, "Process %d does not exist or is not accessible.\n", (int)pid );
        return 1;
    }
    if( !ProcessIsAlive( pid ) )
    {
        fprintf( stderr, "Process %d is a zombie (it has already exited); nothing to attach to.\n", (int)pid );
        return 1;
    }

    s_targetPid = pid;

    printf( "Attaching to process %d", (int)pid );
    fflush( stdout );

    if( !tracy::InitExternalTarget( pid ) ) return 1;

    printf( " (%s)...\n", tracy::GetExternalTargetName() );
    fflush( stdout );

    bool kernelFrames = false;
    bool hwStats = false;
    int hwErrno = 0;
    if( !PreflightSamplingEvent( pid, kernelFrames, hwStats, hwErrno ) ) return 1;

    if( !GetTraceFsPath() )
    {
        fprintf( stderr, "No tracefs mount found: the client's system tracing cannot start without it, so no samples would be captured.\n" );
        return 1;
    }

    tracy::StartupProfiler();
    if( tracy::IsSystemTracingFailed() )
    {
        fprintf( stderr, "The client failed to start sampling although the preflight passed; the capture would contain no samples (the target may have exited between checks, or the kernel rejected the event setup).\n" );
        tracy::ShutdownProfiler();
        return 1;
    }
    if( !VerifyClientListening() )
    {
        if( const char* port = getenv( "TRACY_PORT" ) )
        {
            fprintf( stderr, "The client could not listen on port %s (the port is most likely in use, or the bind was denied). Retry, or choose another port with --port.\n", port );
        }
        else
        {
            fprintf( stderr, "The client could not listen on any of the scan ports 8086-8105 (they are most likely all in use, or the bind was denied). Retry, or choose another port with --port.\n" );
        }
        tracy::ShutdownProfiler();
        return 1;
    }

    PrintStartupReport( kernelFrames, hwStats, hwErrno );

    // Wait for the target process to exit, or for a signal
    while( !s_shouldQuit && ProcessIsAlive( pid ) )
    {
        usleep( 100000 );  // 100ms poll
    }

    if( s_shouldQuit )
    {
        printf( "\nShutting down profiler...\n" );
    }
    else
    {
        printf( "Target exited.\n" );
    }

    tracy::ShutdownProfiler();
    return 0;
}

static int RunForked( int argc, char** argv )
{
    pid_t childPid = fork();
    if( childPid < 0 )
    {
        fprintf( stderr, "Unable to fork: %s\n", strerror( errno ) );
        return 2;
    }

    if( childPid == 0 )
    {
        // Child process: request ptrace stop at exec, then exec the target.
        // Don't leak the monitor's own TRACY_* env into a target that links its own client.
        unsetenv( "TRACY_SAMPLING_HZ" );
        unsetenv( "TRACY_PORT" );
        if( ptrace( PTRACE_TRACEME, 0, nullptr, nullptr ) < 0 )
        {
            fprintf( stderr, "ptrace(TRACEME) failed: %s\n", strerror( errno ) );
            _exit( 2 );
        }
        execvp( argv[0], argv );
        fprintf( stderr, "Unable to exec '%s': %s\n", argv[0], strerror( errno ) );
        _exit( 2 );
    }

    // Parent: wait for the child to stop at the exec boundary (SIGTRAP)
    s_targetPid = childPid;
    s_isForked = true;

    int status;
    for(;;)
    {
        if( waitpid( childPid, &status, 0 ) >= 0 ) break;
        if( errno == EINTR ) continue;
        fprintf( stderr, "waitpid failed: %s\n", strerror( errno ) );
        kill( childPid, SIGKILL );
        waitpid( childPid, nullptr, 0 );
        return 2;
    }

    while( WIFSTOPPED( status ) && WSTOPSIG( status ) != SIGTRAP )
    {
        // A caught signal (the handlers are inherited by the child) arriving between
        // PTRACE_TRACEME and exec produces a signal-delivery stop before the exec stop.
        // Re-inject it and keep waiting for the exec stop: running the setup on the
        // pre-exec child would capture the monitor's own image and mis-symbolicate.
        // Job-control signals must never be re-injected: re-delivering SIGSTOP/SIGTSTP
        // re-stops the child, so the exec stop would never be reached (or, for a
        // stop carrying the 0x80 job-control bit, PTRACE_CONT rejects the signal
        // number outright). Resume those without a signal instead: the stop is
        // delivered as a group stop at most once more, and the next resume lifts it.
        const int rawStopSig = WSTOPSIG( status );
        const int stopSig = rawStopSig & 0x7f;
        const int resumeSig = ( rawStopSig & 0x80 || stopSig == SIGSTOP || stopSig == SIGTSTP ) ? 0 : stopSig;
        if( ptrace( PTRACE_CONT, childPid, 0, (void*)(unsigned long)resumeSig ) != 0 )
        {
            fprintf( stderr, "ptrace failed: %s\n", strerror( errno ) );
            kill( childPid, SIGKILL );
            waitpid( childPid, nullptr, 0 );
            return 2;
        }
        for(;;)
        {
            if( waitpid( childPid, &status, 0 ) >= 0 ) break;
            if( errno == EINTR ) continue;
            fprintf( stderr, "waitpid failed: %s\n", strerror( errno ) );
            kill( childPid, SIGKILL );
            waitpid( childPid, nullptr, 0 );
            return 2;
        }
    }

    if( !WIFSTOPPED( status ) )
    {
        // Child exited or was killed before reaching the post-exec SIGTRAP.
        if( s_shouldQuit )
        {
            fprintf( stderr, "\nInterrupted before target started.\n" );
        }
        else if( WIFEXITED( status ) )
        {
            fprintf( stderr, "Target exited before profiling began (status %d) -- exec failed?\n", WEXITSTATUS( status ) );
        }
        else if( WIFSIGNALED( status ) )
        {
            fprintf( stderr, "Target killed by signal %d before profiling began.\n", WTERMSIG( status ) );
        }
        else
        {
            fprintf( stderr, "Child process did not stop as expected (status=0x%x).\n", status );
        }
        return 2;
    }

    // The child is stopped post-exec: read its name/exe/maps and check sampling
    // permissions while we hold it stopped.
    if( !tracy::InitExternalTarget( childPid ) )
    {
        kill( childPid, SIGKILL );
        waitpid( childPid, nullptr, 0 );
        return 1;
    }

    printf( "Profiling '%s' (pid %d)...\n", tracy::GetExternalTargetName(), (int)childPid );
    fflush( stdout );

    bool kernelFrames = false;
    bool hwStats = false;
    int hwErrno = 0;
    if( !PreflightSamplingEvent( childPid, kernelFrames, hwStats, hwErrno ) )
    {
        kill( childPid, SIGKILL );
        waitpid( childPid, nullptr, 0 );
        return 1;
    }

    if( !GetTraceFsPath() )
    {
        fprintf( stderr, "No tracefs mount found: the client's system tracing cannot start without it, so no samples would be captured.\n" );
        kill( childPid, SIGKILL );
        waitpid( childPid, nullptr, 0 );
        return 1;
    }

    tracy::StartupProfiler();
    if( tracy::IsSystemTracingFailed() )
    {
        fprintf( stderr, "The client failed to start sampling although the preflight passed; the capture would contain no samples (the target may have exited between checks, or the kernel rejected the event setup).\n" );
        kill( childPid, SIGKILL );
        waitpid( childPid, nullptr, 0 );
        tracy::ShutdownProfiler();
        return 1;
    }

    // Detach ptrace and let the child run. If detach fails the child stays
    // stopped forever, so this has to be fatal.
    if( ptrace( PTRACE_DETACH, childPid, nullptr, nullptr ) < 0 )
    {
        fprintf( stderr, "ptrace(DETACH) failed: %s -- killing child.\n", strerror( errno ) );
        kill( childPid, SIGKILL );
        waitpid( childPid, nullptr, 0 );
        tracy::ShutdownProfiler();
        return 2;
    }

    if( !VerifyClientListening() )
    {
        if( const char* port = getenv( "TRACY_PORT" ) )
        {
            fprintf( stderr, "The client could not listen on port %s (the port is most likely in use, or the bind was denied). Retry, or choose another port with --port.\n", port );
        }
        else
        {
            fprintf( stderr, "The client could not listen on any of the scan ports 8086-8105 (they are most likely all in use, or the bind was denied). Retry, or choose another port with --port.\n" );
        }
        kill( childPid, SIGKILL );
        waitpid( childPid, nullptr, 0 );
        tracy::ShutdownProfiler();
        return 1;
    }

    PrintStartupReport( kernelFrames, hwStats, hwErrno );

    // Wait for child to exit, or for a signal
    for(;;)
    {
        if( s_shouldQuit ) break;

        int wstatus;
        pid_t ret = waitpid( childPid, &wstatus, WNOHANG );
        if( ret > 0 )
        {
            // the monitor's exit code reflects the monitor, not the profiled application
            if( WIFEXITED( wstatus ) )
            {
                printf( "Target exited with status %d.\n", WEXITSTATUS( wstatus ) );
            }
            else if( WIFSIGNALED( wstatus ) )
            {
                printf( "Target exited (signal %d).\n", WTERMSIG( wstatus ) );
            }
            break;
        }
        else if( ret < 0 && errno != EINTR )
        {
            // Child already gone
            break;
        }
        usleep( 100000 );
    }

    if( s_shouldQuit && ProcessIsAlive( childPid ) )
    {
        printf( "\nForwarding signal to child and shutting down...\n" );
        kill( childPid, SIGINT );
        // Give it a moment to exit
        usleep( 500000 );
        if( ProcessIsAlive( childPid ) )
        {
            kill( childPid, SIGKILL );
        }
        waitpid( childPid, nullptr, 0 );
    }
    else if( s_shouldQuit )
    {
        // Child is a zombie (it died since the last poll): reap it.
        waitpid( childPid, nullptr, WNOHANG );
    }

    tracy::ShutdownProfiler();
    return 0;
}

// Reserve the first free port in the client's 8086..8105 scan range and hand the
// probe socket to the client (SetReservedListenSocket) so the reservation is atomic.
// The probe must mirror the client's bind exactly (ListenSocket::Listen): IPv6
// dual-stack first, IPv4 only if socket() itself fails, SO_REUSEADDR,
// TRACY_ONLY_LOCALHOST narrows to loopback, fd CLOEXEC (no leak into the target).
static bool ProbeClientBind( int port, bool ipv4Only, bool onlyLocalhost, int& fdOut )
{
    fdOut = -1;
    int s = -1;
    int family = AF_INET6;
    if( !ipv4Only ) s = socket( AF_INET6, SOCK_STREAM, 0 );
    if( s < 0 )
    {
        family = AF_INET;
        s = socket( AF_INET, SOCK_STREAM, 0 );
    }
    if( s < 0 ) return false;
    fcntl( s, F_SETFD, FD_CLOEXEC );
    int val = 1;
    setsockopt( s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof( val ) );
    bool ok = false;
    if( family == AF_INET6 )
    {
        sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        if( onlyLocalhost ) addr.sin6_addr = in6addr_loopback;
        addr.sin6_port = htons( (uint16_t)port );
        ok = bind( s, (sockaddr*)&addr, sizeof( addr ) ) == 0 && listen( s, 4 ) == 0;
    }
    else
    {
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = onlyLocalhost ? htonl( INADDR_LOOPBACK ) : INADDR_ANY;
        addr.sin_port = htons( (uint16_t)port );
        ok = bind( s, (sockaddr*)&addr, sizeof( addr ) ) == 0 && listen( s, 4 ) == 0;
    }
    if( ok )
    {
        fdOut = s;
    }
    else
    {
        close( s );
    }
    return ok;
}

static void ReservePortIfUnpinned()
{
    if( getenv( "TRACY_PORT" ) ) return;
    const char* onlyIPv4 = getenv( "TRACY_ONLY_IPV4" );
    const char* onlyLocalhost = getenv( "TRACY_ONLY_LOCALHOST" );
    const bool ipv4Only = onlyIPv4 && onlyIPv4[0] == '1';
    const bool localhost = onlyLocalhost && onlyLocalhost[0] == '1';
    for( int i=0; i<20; i++ )
    {
        const int port = 8086 + i;
        int fd = -1;
        if( ProbeClientBind( port, ipv4Only, localhost, fd ) )
        {
            char buf[8];
            snprintf( buf, sizeof( buf ), "%d", port );
            setenv( "TRACY_PORT", buf, 1 );
            tracy::SetReservedListenSocket( fd );
            return;
        }
    }
}

int main( int argc, char** argv )
{
    auto progName = argv[0];

    if( argc < 2 )
    {
        PrintUsage( progName );
        return 1;
    }

    // Install signal handlers for graceful shutdown
    struct sigaction sa = {};
    sa.sa_handler = SignalHandler;
    sigemptyset( &sa.sa_mask );
    sa.sa_flags = 0;
    sigaction( SIGINT, &sa, nullptr );
    sigaction( SIGTERM, &sa, nullptr );
    sigaction( SIGHUP, &sa, nullptr );
    sigaction( SIGQUIT, &sa, nullptr );

    // TRACY_NO_SYS_TRACE / TRACY_NO_SAMPLING would silently disable the monitor's
    // primary data sources (IsSystemTracingFailed() stays false); refuse them up front.
    const char* noSysTrace = getenv( "TRACY_NO_SYS_TRACE" );
    const char* noSampling = getenv( "TRACY_NO_SAMPLING" );
    if( ( noSysTrace && noSysTrace[0] == '1' ) || ( noSampling && noSampling[0] == '1' ) )
    {
        if( noSysTrace && noSysTrace[0] == '1' )
        {
            fprintf( stderr, "tracy-monitor: TRACY_NO_SYS_TRACE=1 is set; the monitor requires system tracing. Unset the variable and retry.\n" );
        }
        if( noSampling && noSampling[0] == '1' )
        {
            fprintf( stderr, "tracy-monitor: TRACY_NO_SAMPLING=1 is set; the monitor requires callstack sampling. Unset the variable and retry.\n" );
        }
        return 1;
    }

    pid_t attachPid = 0;
    char attachName[128] = {};
    bool wantAttach = false;

    enum { OptHz = 256, OptPort };

    static struct option longOptions[] =
    {
        { "pid",  required_argument, nullptr, 'p' },
        { "name", required_argument, nullptr, 'n' },
        { "hz",   required_argument, nullptr, OptHz },
        { "port", required_argument, nullptr, OptPort },
        { "help", no_argument,       nullptr, 'h' },
        { nullptr, 0, nullptr, 0 }
    };

    int c;
    while( ( c = getopt_long( argc, argv, "+p:n:h", longOptions, nullptr ) ) != -1 )
    {
        switch( c )
        {
        case 'p':
            attachPid = atoi( optarg );
            wantAttach = true;
            break;
        case 'n':
            if( strlen( optarg ) >= sizeof( attachName ) )
            {
                fprintf( stderr, "Process name too long (max %zu characters).\n", sizeof( attachName ) - 1 );
                return 1;
            }
            snprintf( attachName, sizeof( attachName ), "%s", optarg );
            wantAttach = true;
            break;
        case OptHz:
        {
            const int hz = atoi( optarg );
            if( hz < 1 || hz > 1000000 )
            {
                fprintf( stderr, "Invalid sample rate %s (range 1..1000000 Hz).\n", optarg );
                return 1;
            }
            char buf[16];
            snprintf( buf, sizeof( buf ), "%d", hz );
            setenv( "TRACY_SAMPLING_HZ", buf, 1 );
            break;
        }
        case OptPort:
        {
            const int port = atoi( optarg );
            if( port < 1 || port > 65535 )
            {
                fprintf( stderr, "Invalid port %s (range 1..65535).\n", optarg );
                return 1;
            }
            char buf[8];
            snprintf( buf, sizeof( buf ), "%d", port );
            setenv( "TRACY_PORT", buf, 1 );
            break;
        }
        case 'h':
            PrintUsage( argv[0] );
            return 0;
        case '?':
            fprintf( stderr, "Unknown option. Use -h for help.\n" );
            return 1;
        }
    }

    // validate a pinned TRACY_PORT like --port: the client pins to any nonzero value
    // (single listen, no fallback), so a bad value would report a port never used.
    {
        const char* portEnv = getenv( "TRACY_PORT" );
        if( portEnv )
        {
            char* end = nullptr;
            const long port = strtol( portEnv, &end, 10 );
            if( end == portEnv || *end != '\0' || port < 1 || port > 65535 )
            {
                fprintf( stderr, "Invalid TRACY_PORT '%s' (expected a number in 1..65535); unset it or use --port.\n", portEnv );
                return 1;
            }
        }
    }
    ReservePortIfUnpinned();
    if( wantAttach )
    {
        if( attachName[0] )
        {
            pid_t pids[32] = {};
            const int numPids = FindPidsByComm( attachName, pids, 32 );
            if( numPids == 0 )
            {
                fprintf( stderr, "No process named '%s' (names are /proc/<pid>/comm values, truncated to 15 characters).\n", attachName );
                return 1;
            }
            if( numPids > 1 )
            {
                fprintf( stderr, "Several processes named '%s':", attachName );
                for( int i=0; i<numPids; i++ ) fprintf( stderr, " %d", (int)pids[i] );
                fprintf( stderr, "\nUse -p PID to disambiguate.\n" );
                return 1;
            }
            return RunAttached( pids[0] );
        }

        if( attachPid <= 0 )
        {
            fprintf( stderr, "Invalid PID specified.\n" );
            return 1;
        }
        return RunAttached( attachPid );
    }

    argv += optind;
    argc -= optind;

    if( argc < 1 )
    {
        PrintUsage( progName );  // argv[0] was shifted, use original
        return 1;
    }

    return RunForked( argc, argv );
}
