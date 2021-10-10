#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#endif

#include <chrono>
#include <inttypes.h>
#include <mutex>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "../../common/TracyProtocol.hpp"
#include "../../common/TracyStackFrames.hpp"
#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyMemory.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracyWorker.hpp"

#ifdef _WIN32
#  include "../../getopt/getopt.h"
#endif


bool disconnect = false;

void SigInt( int )
{
    disconnect = true;
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
    while( !worker.IsConnected() )
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
    }
    while( !worker.HasData() ) std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
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
        if( disconnect )
        {
            worker.Disconnect();
            disconnect = false;
            break;
        }

        lock.lock();
        const auto mbps = worker.GetMbpsData().back();
        const auto compRatio = worker.GetCompRatio();
        const auto netTotal = worker.GetDataTransferred();
        lock.unlock();

        if( mbps < 0.1f )
        {
            printf( "\33[2K\r\033[36;1m%7.2f Kbps", mbps * 1000.f );
        }
        else
        {
            printf( "\33[2K\r\033[36;1m%7.2f Mbps", mbps );
        }
        printf( " \033[0m /\033[36;1m%5.1f%% \033[0m=\033[33;1m%7.2f Mbps \033[0m| \033[33mNet: \033[32m%s \033[0m| \033[33mMem: \033[31;1m%s\033[0m | \033[33mTime: %s\033[0m",
            compRatio * 100.f,
            mbps / compRatio,
            tracy::MemSizeToString( netTotal ),
            tracy::MemSizeToString( tracy::memUsage ),
            tracy::TimeToString( worker.GetLastTime() ) );
        fflush( stdout );

        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
        if( seconds != -1 )
        {
            const auto dur = std::chrono::high_resolution_clock::now() - t0;
            if( std::chrono::duration_cast<std::chrono::seconds>(dur).count() >= seconds )
            {
                disconnect = true;
            }
        }
    }
    const auto t1 = std::chrono::high_resolution_clock::now();

    const auto& failure = worker.GetFailureType();
    if( failure != tracy::Worker::Failure::None )
    {
        printf( "\n\033[31;1mInstrumentation failure: %s\033[0m", tracy::Worker::GetFailureString( failure ) );
        auto& fd = worker.GetFailureData();
        if( !fd.message.empty() )
        {
            printf( "\nContext: %s", fd.message.c_str() );
        }
        if( fd.callstack != 0 )
        {
            printf( "\n\033[1mFailure callstack:\033[0m\n" );
            auto& cs = worker.GetCallstack( fd.callstack );
            int fidx = 0;
            int bidx = 0;
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

                        bidx++;

                        if( f == fsz-1 )
                        {
                            printf( "%3i. ", fidx++ );
                        }
                        else
                        {
                            printf( "\033[30;1minl. " );
                        }
                        printf( "\033[0;36m%s  ", txt );
                        txt = worker.GetString( frame.file );
                        if( frame.line == 0 )
                        {
                            printf( "\033[33m(%s)", txt );
                        }
                        else
                        {
                            printf( "\033[33m(%s:%" PRIu32 ")", txt, frame.line );
                        }
                        if( frameData->imageName.Active() )
                        {
                            printf( "\033[35m %s\033[0m\n", worker.GetString( frameData->imageName ) );
                        }
                        else
                        {
                            printf( "\033[0m\n" );
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
        printf( " \033[32;1mdone!\033[0m\n" );
        f->Finish();
        const auto stats = f->GetCompressionStatistics();
        printf( "Trace size %s (%.2f%% ratio)\n", tracy::MemSizeToString( stats.second ), 100.f * stats.second / stats.first );
    }
    else
    {
        printf( " \033[31;1failed!\033[0m\n" );
    }

    return 0;
}
