#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../public/tracy/Tracy.hpp"
#include "../public/common/TracyVersion.hpp"
#include "../public/client/TracyCallstack.hpp"
#include "GitRef.hpp"

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

static void PrintUsage( const char* progName )
{
    printf( "tracy-monitor %i.%i.%i / %s\n\n", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
    printf( "Usage: %s [OPTIONS] program [arguments...]\n", progName );
    printf( "       %s [OPTIONS] -p PID\n", progName );
    printf( "\n" );
    printf( "Options:\n" );
    printf( "  -p PID        Attach to existing process (PID)\n" );
    printf( "  -h            Show this help message\n" );
    printf( "\n" );
    printf( "Examples:\n" );
    printf( "  %s ./my_program arg1 arg2\n", progName );
    printf( "  %s -p 1234\n", progName );
    printf( "\n" );
    printf( "The monitor captures sampling profiling data from an external process\n" );
    printf( "and streams it to a Tracy server for visualization.\n" );
    printf( "\n" );
    printf( "In launch mode, the target program is started under ptrace control to\n" );
    printf( "ensure profiling begins before the first instruction executes.\n" );
    printf( "\n" );
    printf( "In attach mode (-p), the target must already be running.\n" );
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

    tracy::StartupProfiler();

    printf( "Profiling started. Waiting for Tracy server connection...\n" );

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
        // Child process: request ptrace stop at exec, then exec the target
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

    tracy::StartupProfiler();

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

    printf( "Profiling started. Waiting for Tracy server connection...\n" );

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

    pid_t attachPid = 0;
    bool wantAttach = false;

    static struct option longOptions[] = {
        { "pid", required_argument, nullptr, 'p' },
        { "help", no_argument, nullptr, 'h' },
        { nullptr, 0, nullptr, 0 }
    };

    int c;
    while( ( c = getopt_long( argc, argv, "+p:h", longOptions, nullptr ) ) != -1 )
    {
        switch( c )
        {
        case 'p':
            attachPid = atoi( optarg );
            wantAttach = true;
            break;
        case 'h':
            PrintUsage( argv[0] );
            return 0;
        case '?':
            fprintf( stderr, "Unknown option. Use -h for help.\n" );
            return 1;
        }
    }

    argv += optind;
    argc -= optind;

    if( wantAttach )
    {
        if( attachPid <= 0 )
        {
            fprintf( stderr, "Invalid PID specified.\n" );
            return 1;
        }
        return RunAttached( attachPid );
    }

    if( argc < 1 )
    {
        PrintUsage( progName );  // argv[0] was shifted, use original
        return 1;
    }

    return RunForked( argc, argv );
}
