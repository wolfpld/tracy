#ifdef _WIN32
#  include <windows.h>
#endif

#include <chrono>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyVersion.hpp"
#include "../../server/TracyWorker.hpp"

#ifdef __CYGWIN__
#  define ftello64(x) ftello(x)
#elif defined _WIN32
#  define ftello64(x) _ftelli64(x)
#endif

void Usage()
{
    printf( "Usage: update [--hc|--extreme] input.tracy output.tracy\n\n" );
    printf( "  --hc: enable LZ4HC compression\n" );
    printf( "  --extreme: enable extreme LZ4HC compression (very slow)\n" );
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

    tracy::FileWrite::Compression clev = tracy::FileWrite::Compression::Fast;

    if( argc != 3 && argc != 4 ) Usage();
    if( argc == 4 )
    {
        if( strcmp( argv[1], "--hc" ) == 0 )
        {
            clev = tracy::FileWrite::Compression::Slow;
        }
        else if( strcmp( argv[1], "--extreme" ) == 0 )
        {
            clev = tracy::FileWrite::Compression::Extreme;
        }
        else
        {
            Usage();
        }
        argv++;
    }

    const char* input = argv[1];
    const char* output = argv[2];

    printf( "Loading...\r" );
    fflush( stdout );
    auto f = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( input ) );
    if( !f )
    {
        fprintf( stderr, "Cannot open input file!\n" );
        exit( 1 );
    }

    try
    {
        int inVer;
        {
            tracy::Worker worker( *f, tracy::EventType::All, false );

#ifndef TRACY_NO_STATISTICS
            while( !worker.AreSourceLocationZonesReady() ) std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
#endif

            auto w = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( output, clev ) );
            if( !w )
            {
                fprintf( stderr, "Cannot open output file!\n" );
                exit( 1 );
            }
            printf( "Saving... \r" );
            fflush( stdout );
            worker.Write( *w );
            inVer = worker.GetTraceVersion();
        }

        FILE* in = fopen( input, "rb" );
        fseek( in, 0, SEEK_END );
        const auto inSize = ftello64( in );
        fclose( in );

        FILE* out = fopen( output, "rb" );
        fseek( out, 0, SEEK_END );
        const auto outSize = ftello64( out );
        fclose( out );

        printf( "%s (%i.%i.%i) {%zu KB} -> %s (%i.%i.%i) {%zu KB}  %.2f%% size change\n", input, inVer >> 16, ( inVer >> 8 ) & 0xFF, inVer & 0xFF, size_t( inSize / 1024 ), output, tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, size_t( outSize / 1024 ), float( outSize ) / inSize * 100 );
    }
    catch( const tracy::UnsupportedVersion& e )
    {
        fprintf( stderr, "The file you are trying to open is from the future version.\n" );
        exit( 1 );
    }
    catch( const tracy::NotTracyDump& e )
    {
        fprintf( stderr, "The file you are trying to open is not a tracy dump.\n" );
        exit( 1 );
    }
    catch( const tracy::LegacyVersion& e )
    {
        fprintf( stderr, "The file you are trying to open is from a legacy version.\n" );
        exit( 1 );
    }

    return 0;
}
