#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracySysUtil.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../public/common/TracyVersion.hpp"
#include "GitRef.hpp"

#include "CaptureOutput.hpp"

#ifdef _WIN32
#  include "../../getopt/getopt.h"
#endif


// This atomic is written by a signal handler (SigInt). Traditionally that would
// have had to be `volatile sig_atomic_t`, and annoyingly, `bool` was
// technically not allowed there, even though in practice it would work.
// The good thing with C++11 atomics is that we can use atomic<bool> instead
// here and be on the actually supported path.
static std::atomic<bool> s_disconnect { false };

void SigInt( int )
{
    s_disconnect.store(true, std::memory_order_relaxed);
}

[[noreturn]] void Usage()
{
    printf( "tracy-capture %i.%i.%i / %s\n\n", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
    printf( "Usage: capture -o output.tracy [-a address] [-p port] [-f] [-s seconds] [-m memlimit]\n" );
    exit( 1 );
}

int main( int argc, char** argv )
{
#ifdef _WIN32
    if( !AttachConsole( ATTACH_PARENT_PROCESS ) )
    {
        AllocConsole();
        SetConsoleMode( GetStdHandle( STD_OUTPUT_HANDLE ), 0x07 );
    }
#endif

    InitTerminalDetection();

    bool overwrite = false;
    const char* address = "127.0.0.1";
    const char* output = nullptr;
    int port = 8086;
    int seconds = -1;
    int64_t memoryLimit = -1;

    int c;
    while( ( c = getopt( argc, argv, "a:o:p:fs:m:" ) ) != -1 )
    {
        switch( c )
        {
        case 'a':
            address = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        case 'p':
            port = atoi( optarg );
            break;
        case 'f':
            overwrite = true;
            break;
        case 's':
            seconds = atoi(optarg);
            break;
        case 'm':
            memoryLimit = std::clamp( atoll( optarg ), 1ll, 999ll ) * tracy::GetPhysicalMemorySize() / 100;
            break;
        default:
            Usage();
            break;
        }
    }

    if( !address || !output ) Usage();

    struct stat st;
    if( stat( output, &st ) == 0 && !overwrite )
    {
        printf( "Output file %s already exists! Use -f to force overwrite.\n", output );
        return 4;
    }

    FILE* test = fopen( output, "wb" );
    if( !test )
    {
        printf( "Cannot open output file %s for writing!\n", output );
        return 5;
    }
    fclose( test );
    unlink( output );

    printf( "Connecting to %s:%i...", address, port );
    fflush( stdout );
    tracy::Worker worker( address, port, memoryLimit );
    int result = WaitForConnection( worker );
    if( result != 0 ) return result;
    printf( "\nTimer resolution: %s\n", tracy::TimeToString( worker.GetResolution() ) );

#ifdef _WIN32
    signal( SIGINT, SigInt );
#else
    struct sigaction sigint, oldsigint;
    memset( &sigint, 0, sizeof( sigint ) );
    sigint.sa_handler = SigInt;
    sigaction( SIGINT, &sigint, &oldsigint );
#endif

    const auto firstTime = worker.GetFirstTime();

    const auto t0 = std::chrono::high_resolution_clock::now();
    while( worker.IsConnected() )
    {
        if( s_disconnect.load( std::memory_order_relaxed ) )
        {
            worker.Disconnect();
            s_disconnect.store(false, std::memory_order_relaxed );
            break;
        }

        PrintCaptureProgress( worker, firstTime, memoryLimit );

        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
        if( seconds != -1 )
        {
            const auto dur = std::chrono::high_resolution_clock::now() - t0;
            if( std::chrono::duration_cast<std::chrono::seconds>(dur).count() >= seconds )
            {
                s_disconnect.store(true, std::memory_order_relaxed );
            }
        }
    }
    const auto t1 = std::chrono::high_resolution_clock::now();

    PrintWorkerFailure( worker );

    printf( "\nFrames: %" PRIu64 "\nTime span: %s\nZones: %s\nElapsed time: %s\nSaving trace...",
        worker.GetFrameCount( *worker.GetFramesBase() ), tracy::TimeToString( worker.GetLastTime() - firstTime ), tracy::RealToString( worker.GetZoneCount() ),
        tracy::TimeToString( std::chrono::duration_cast<std::chrono::nanoseconds>( t1 - t0 ).count() ) );
    fflush( stdout );
    auto f = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( output, tracy::FileCompression::Zstd, 3, 4 ) );
    if( f )
    {
        worker.Write( *f, false );
        AnsiPrintf( ANSI_GREEN ANSI_BOLD, " done!\n" );
        f->Finish();
        const auto stats = f->GetCompressionStatistics();
        printf( "Trace size %s (%.2f%% ratio)\n", tracy::MemSizeToString( stats.second ), 100.f * stats.second / stats.first );
    }
    else
    {
        AnsiPrintf( ANSI_RED ANSI_BOLD, " failed!\n");
    }

    return 0;
}
