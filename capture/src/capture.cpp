#ifdef _WIN32
#  include <windows.h>
#endif

#include <chrono>
#include <inttypes.h>
#include <mutex>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyMemory.hpp"
#include "../../server/TracyWorker.hpp"
#include "getopt.h"

static const char* TimeToString( int64_t ns )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    const char* sign = "";
    if( ns < 0 )
    {
        sign = "-";
        ns = -ns;
    }

    if( ns < 1000 )
    {
        sprintf( buf, "%s%" PRIi64 " ns", sign, ns );
    }
    else if( ns < 1000ll * 1000 )
    {
        sprintf( buf, "%s%.2f us", sign, ns / 1000. );
    }
    else if( ns < 1000ll * 1000 * 1000 )
    {
        sprintf( buf, "%s%.2f ms", sign, ns / ( 1000. * 1000. ) );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 )
    {
        sprintf( buf, "%s%.2f s", sign, ns / ( 1000. * 1000. * 1000. ) );
    }
    else
    {
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) );
        const auto s = int64_t( ns - m * ( 1000ll * 1000 * 1000 * 60 ) );
        sprintf( buf, "%s%" PRIi64 ":%04.1f", sign, m, s / ( 1000. * 1000. * 1000. ) );
    }
    return buf;
}

static const char* RealToString( double val, bool separator )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    sprintf( buf, "%f", val );
    auto ptr = buf;
    if( *ptr == '-' ) ptr++;

    const auto vbegin = ptr;

    if( separator )
    {
        while( *ptr != '\0' && *ptr != ',' && *ptr != '.' ) ptr++;
        auto end = ptr;
        while( *end != '\0' ) end++;
        auto sz = end - ptr;

        while( ptr - vbegin > 3 )
        {
            ptr -= 3;
            memmove( ptr+1, ptr, sz );
            *ptr = ',';
            sz += 4;
        }
    }

    while( *ptr != '\0' && *ptr != ',' && *ptr != '.' ) ptr++;

    if( *ptr == '\0' ) return buf;
    while( *ptr != '\0' ) ptr++;
    ptr--;
    while( *ptr == '0' && *ptr != ',' && *ptr != '.' ) ptr--;
    if( *ptr != '.' && *ptr != ',' ) ptr++;
    *ptr = '\0';
    return buf;
}


void Usage()
{
    printf( "Usage: capture -a address -o output.tracy\n" );
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

    const char* address = nullptr;
    const char* output = nullptr;

    int c;
    while( ( c = getopt( argc, argv, "a:o:" ) ) != -1 )
    {
        switch( c )
        {
        case 'a':
            address = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        default:
            Usage();
            break;
        }
    }

    if( !address || !output ) Usage();

    printf( "Connecting to %s...", address );
    fflush( stdout );
    tracy::Worker worker( address );
    while( !worker.HasData() ) std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
    printf( "\nQueue delay: %s\nTimer resolution: %s\n", TimeToString( worker.GetDelay() ), TimeToString( worker.GetResolution() ) );

    auto& lock = worker.GetMbpsDataLock();

    while( worker.IsConnected() )
    {
        lock.lock();
        const auto mbps = worker.GetMbpsData().back();
        const auto compRatio = worker.GetCompRatio();
        lock.unlock();

        if( mbps < 0.1f )
        {
            printf( "\33[2K\r\033[36;1m%7.2f Kbps", mbps * 1000.f );
        }
        else
        {
            printf( "\33[2K\r\033[36;1m%7.2f Mbps", mbps );
        }
        printf( " \033[0m| Ratio: \033[36;1m%5.1f%% \033[0m| Real: \033[33;1m%7.2f Mbps \033[0m| Mem: \033[31;1m%.2f MB\033[0m", compRatio * 100.f, mbps / compRatio, tracy::memUsage.load( std::memory_order_relaxed ) / ( 1024.f * 1024.f ) );
        fflush( stdout );

        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
    }

    printf( "\nFrames: %" PRIu64 "\nTime span: %s\nZones: %s\nSaving trace...", worker.GetFrameCount(), TimeToString( worker.GetLastTime() - worker.GetFrameBegin( 0 ) ), RealToString( worker.GetZoneCount(), true ) );
    fflush( stdout );
    auto f = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( output ) );
    if( f )
    {
        worker.Write( *f );
        printf( " \033[32;1mdone!\033[0m\n" );
    }
    else
    {
        printf( " \033[31;1failed!\033[0m\n" );
    }

    return 0;
}
