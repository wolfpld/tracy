#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../public/tracy/Tracy.hpp"
#include "../public/common/TracyVersion.hpp"
#include "../public/client/TracyCallstack.hpp"
#include "GitRef.hpp"

namespace tracy {
    extern uint32_t ___tracy_magic_pid_override;
    extern char ___tracy_magic_process_name[64];
}

static volatile sig_atomic_t s_shouldQuit = 0;
static pid_t s_targetPid = 0;
static bool s_isForked = false;

static void SignalHandler( int sig )
{
    s_shouldQuit = 1;
}

static bool ReadProcessName( pid_t pid, char* buf, size_t bufSize )
{
    char path[64];
    snprintf( path, sizeof( path ), "/proc/%d/comm", (int)pid );
    FILE* f = fopen( path, "r" );
    if( !f ) return false;
    if( !fgets( buf, bufSize, f ) )
    {
        fclose( f );
        return false;
    }
    fclose( f );
    // Remove trailing newline
    size_t len = strlen( buf );
    while( len > 0 && ( buf[len-1] == '\n' || buf[len-1] == '\r' ) ) len--;
    buf[len] = '\0';
    return len > 0;
}

static bool CheckPerfPermissions()
{
    FILE* f = fopen( "/proc/sys/kernel/perf_event_paranoid", "r" );
    if( !f )
    {
        fprintf( stderr, "Warning: Cannot read /proc/sys/kernel/perf_event_paranoid\n" );
        return true;  // Assume OK
    }
    int paranoid = 2;
    if( fscanf( f, "%d", &paranoid ) != 1 ) paranoid = 2;
    fclose( f );

    if( paranoid > 1 && geteuid() != 0 )
    {
        fprintf( stderr, "Warning: perf_event_paranoid = %d. Profiling another process may require:\n", paranoid );
        fprintf( stderr, "  - Running as root, or\n" );
        fprintf( stderr, "  - Setting /proc/sys/kernel/perf_event_paranoid to -1 or 0, or\n" );
        fprintf( stderr, "  - Granting CAP_PERFMON + CAP_SYS_PTRACE capabilities\n" );
    }
    return true;
}

static bool ProcessIsAlive( pid_t pid )
{
    return kill( pid, 0 ) == 0;
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
    if( !ProcessIsAlive( pid ) )
    {
        fprintf( stderr, "Process %d does not exist or is not accessible.\n", (int)pid );
        return 1;
    }

    s_targetPid = pid;

    char procName[64];
    if( ReadProcessName( pid, procName, sizeof( procName ) ) )
    {
        memcpy( tracy::___tracy_magic_process_name, procName, sizeof( tracy::___tracy_magic_process_name ) );
    }

    printf( "Attaching to process %d", (int)pid );
    if( tracy::___tracy_magic_process_name[0] ) printf( " (%s)", tracy::___tracy_magic_process_name );
    printf( "...\n" );

    tracy::InitExternalImageCache( pid );
    tracy::___tracy_magic_pid_override = (uint32_t)pid;
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
        printf( "Target process %d exited.\n", (int)pid );
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
    if( waitpid( childPid, &status, 0 ) < 0 )
    {
        fprintf( stderr, "waitpid failed: %s\n", strerror( errno ) );
        return 2;
    }

    if( !WIFSTOPPED( status ) )
    {
        fprintf( stderr, "Child process did not stop as expected (status=0x%x).\n", status );
        return 2;
    }

    // The child has exec'd but is stopped. Its address space is now the target program.
    // Read its process name and memory maps.
    char procName[64];
    if( ReadProcessName( childPid, procName, sizeof( procName ) ) )
    {
        memcpy( tracy::___tracy_magic_process_name, procName, sizeof( tracy::___tracy_magic_process_name ) );
    }

    printf( "Profiling '%s' (pid %d)...\n",
            tracy::___tracy_magic_process_name[0] ? tracy::___tracy_magic_process_name : argv[0],
            (int)childPid );

    // Initialize the external image cache (target's /proc/pid/maps)
    tracy::InitExternalImageCache( childPid );

    // Set up the profiler to target the child
    tracy::___tracy_magic_pid_override = (uint32_t)childPid;
    tracy::StartupProfiler();

    // Detach ptrace and let the child run
    if( ptrace( PTRACE_DETACH, childPid, nullptr, nullptr ) < 0 )
    {
        fprintf( stderr, "Warning: ptrace(DETACH) failed: %s\n", strerror( errno ) );
        // Not fatal -- the child might still run
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
            if( WIFEXITED( wstatus ) )
            {
                printf( "Target process exited with status %d.\n", WEXITSTATUS( wstatus ) );
            }
            else if( WIFSIGNALED( wstatus ) )
            {
                printf( "Target process killed by signal %d.\n", WTERMSIG( wstatus ) );
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
            waitpid( childPid, nullptr, 0 );
        }
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

    CheckPerfPermissions();

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
