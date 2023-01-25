#ifdef _WIN32
#  include <windows.h>
#  include <io.h>
#else
#  include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <inttypes.h>
#include <mutex>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "../../public/common/TracyProtocol.hpp"
#include "../../public/common/TracyStackFrames.hpp"
#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyMemory.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracyWorker.hpp"

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
    // Relaxed order is closest to a traditional `volatile` write.
    // We don't need stronger ordering since this signal handler doesn't do
    // anything else that would need to be ordered relatively to this.
    s_disconnect.store(true, std::memory_order_relaxed);
}

static bool s_isStdoutATerminal = false;

void InitIsStdoutATerminal() {
#ifdef _WIN32
    s_isStdoutATerminal = _isatty( fileno( stdout ) );
#else
    s_isStdoutATerminal = isatty( fileno( stdout ) );
#endif
}

bool IsStdoutATerminal() { return s_isStdoutATerminal; }

#define ANSI_RESET "\033[0m"
#define ANSI_BOLD "\033[1m"
#define ANSI_BLACK "\033[30m"
#define ANSI_RED "\033[31m"
#define ANSI_GREEN "\033[32m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN "\033[36m"
#define ANSI_ERASE_LINE "\033[2K"

// Like printf, but if stdout is a terminal, prepends the output with
// the given `ansiEscape` and appends ANSI_RESET.
void AnsiPrintf( const char* ansiEscape, const char* format, ... ) {
    if( IsStdoutATerminal() )
    {
        // Prepend ansiEscape and append ANSI_RESET.
        char buf[256];
        va_list args;
        va_start( args, format );
        vsnprintf( buf, sizeof buf, format, args );
        va_end( args );
        printf( "%s%s" ANSI_RESET, ansiEscape, buf );
    }
    else
    {
        // Just a normal printf.
        va_list args;
        va_start( args, format );
        vfprintf( stdout, format, args );
        va_end( args );
    }
}

[[noreturn]] void Usage()
{
    printf( "Usage: capture -o output.tracy [-a address] [-p port] [-f] [-s seconds]\n" );
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

    InitIsStdoutATerminal();

    bool overwrite = false;
    const char* address = "127.0.0.1";
    const char* output = nullptr;
    int port = 8086;
    int seconds = -1;

    int c;
    while( ( c = getopt( argc, argv, "a:o:p:fs:" ) ) != -1 )
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
            seconds = atoi (optarg);
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
    tracy::Worker worker( address, port );
    while( !worker.HasData() )
    {
        const auto handshake = worker.GetHandshakeStatus();
        if( handshake == tracy::HandshakeProtocolMismatch )
        {
            printf( "\nThe client you are trying to connect to uses incompatible protocol version.\nMake sure you are using the same Tracy version on both client and server.\n" );
            return 1;
        }
        if( handshake == tracy::HandshakeNotAvailable )
        {
            printf( "\nThe client you are trying to connect to is no longer able to sent profiling data,\nbecause another server was already connected to it.\nYou can do the following:\n\n  1. Restart the client application.\n  2. Rebuild the client application with on-demand mode enabled.\n" );
            return 2;
        }
        if( handshake == tracy::HandshakeDropped )
        {
            printf( "\nThe client you are trying to connect to has disconnected during the initial\nconnection handshake. Please check your network configuration.\n" );
            return 3;
        }
        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
    }
    printf( "\nQueue delay: %s\nTimer resolution: %s\n", tracy::TimeToString( worker.GetDelay() ), tracy::TimeToString( worker.GetResolution() ) );

#ifdef _WIN32
    signal( SIGINT, SigInt );
#else
    struct sigaction sigint, oldsigint;
    memset( &sigint, 0, sizeof( sigint ) );
    sigint.sa_handler = SigInt;
    sigaction( SIGINT, &sigint, &oldsigint );
#endif

    auto& lock = worker.GetMbpsDataLock();

    const auto t0 = std::chrono::high_resolution_clock::now();
    while( worker.IsConnected() )
    {
        // Relaxed order is sufficient here because `s_disconnect` is only ever
        // set by this thread or by the SigInt handler, and that handler does
        // nothing else than storing `s_disconnect`.
        if( s_disconnect.load( std::memory_order_relaxed ) )
        {
            worker.Disconnect();
            // Relaxed order is sufficient because only this thread ever reads
            // this value.
            s_disconnect.store(false, std::memory_order_relaxed );
            break;
        }

        lock.lock();
        const auto mbps = worker.GetMbpsData().back();
        const auto compRatio = worker.GetCompRatio();
        const auto netTotal = worker.GetDataTransferred();
        lock.unlock();

        // Output progress info only if destination is a TTY to avoid bloating
        // log files (so this is not just about usage of ANSI color codes).
        if( IsStdoutATerminal() )
        {
            const char* unit = "Mbps";
            float unitsPerMbps = 1.f;
            if( mbps < 0.1f )
            {
                unit = "Kbps";
                unitsPerMbps = 1000.f;
            }
            AnsiPrintf( ANSI_ERASE_LINE ANSI_CYAN ANSI_BOLD, "\r%7.2f %s", mbps * unitsPerMbps, unit );
            printf( " /");
            AnsiPrintf( ANSI_CYAN ANSI_BOLD, "%5.1f%%", compRatio * 100.f );
            printf( " =");
            AnsiPrintf( ANSI_YELLOW ANSI_BOLD, "%7.2f Mbps", mbps / compRatio );
            printf( " | ");
            AnsiPrintf( ANSI_YELLOW, "Tx: ");
            AnsiPrintf( ANSI_GREEN, "%s",  tracy::MemSizeToString( netTotal ) );
            printf( " | ");
            AnsiPrintf( ANSI_RED ANSI_BOLD, "%s", tracy::MemSizeToString( tracy::memUsage ) );
            printf( " | ");
            AnsiPrintf( ANSI_RED, "%s", tracy::TimeToString( worker.GetLastTime() ) );
            fflush( stdout );
        }

        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
        if( seconds != -1 )
        {
            const auto dur = std::chrono::high_resolution_clock::now() - t0;
            if( std::chrono::duration_cast<std::chrono::seconds>(dur).count() >= seconds )
            {
                // Relaxed order is sufficient because only this thread ever reads
                // this value.
                s_disconnect.store(true, std::memory_order_relaxed );
            }
        }
    }
    const auto t1 = std::chrono::high_resolution_clock::now();

    const auto& failure = worker.GetFailureType();
    if( failure != tracy::Worker::Failure::None )
    {
        AnsiPrintf( ANSI_RED ANSI_BOLD, "\nInstrumentation failure: %s", tracy::Worker::GetFailureString( failure ) );
        auto& fd = worker.GetFailureData();
        if( !fd.message.empty() )
        {
            printf( "\nContext: %s", fd.message.c_str() );
        }
        if( fd.callstack != 0 )
        {
            AnsiPrintf( ANSI_BOLD, "\n%sFailure callstack:%s\n" );
            auto& cs = worker.GetCallstack( fd.callstack );
            int fidx = 0;
            for( auto& entry : cs )
            {
                auto frameData = worker.GetCallstackFrame( entry );
                if( !frameData )
                {
                    printf( "%3i. %p\n", fidx++, (void*)worker.GetCanonicalPointer( entry ) );
                }
                else
                {
                    const auto fsz = frameData->size;
                    for( uint8_t f=0; f<fsz; f++ )
                    {
                        const auto& frame = frameData->data[f];
                        auto txt = worker.GetString( frame.name );

                        if( fidx == 0 && f != fsz-1 )
                        {
                            auto test = tracy::s_tracyStackFrames;
                            bool match = false;
                            do
                            {
                                if( strcmp( txt, *test ) == 0 )
                                {
                                    match = true;
                                    break;
                                }
                            }
                            while( *++test );
                            if( match ) continue;
                        }

                        if( f == fsz-1 )
                        {
                            printf( "%3i. ", fidx++ );
                        }
                        else
                        {
                            AnsiPrintf( ANSI_BLACK ANSI_BOLD, "inl. " );
                        }
                        AnsiPrintf( ANSI_CYAN, "%s  ", txt );
                        txt = worker.GetString( frame.file );
                        if( frame.line == 0 )
                        {
                            AnsiPrintf( ANSI_YELLOW, "(%s)", txt );
                        }
                        else
                        {
                            AnsiPrintf( ANSI_YELLOW, "(%s:%" PRIu32 ")", txt, frame.line );
                        }
                        if( frameData->imageName.Active() )
                        {
                            AnsiPrintf( ANSI_MAGENTA, " %s\n", worker.GetString( frameData->imageName ) );
                        }
                        else
                        {
                            printf( "\n" );
                        }
                    }
                }
            }
        }
    }

    printf( "\nFrames: %" PRIu64 "\nTime span: %s\nZones: %s\nElapsed time: %s\nSaving trace...",
        worker.GetFrameCount( *worker.GetFramesBase() ), tracy::TimeToString( worker.GetLastTime() ), tracy::RealToString( worker.GetZoneCount() ),
        tracy::TimeToString( std::chrono::duration_cast<std::chrono::nanoseconds>( t1 - t0 ).count() ) );
    fflush( stdout );
    auto f = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( output ) );
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
