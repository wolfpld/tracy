#ifdef _WIN32
#  include <windows.h>
#endif

#include <chrono>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../public/common/TracyVersion.hpp"
#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../zstd/zstd.h"
#include "../../getopt/getopt.h"

#include "OfflineSymbolResolver.h"

#ifdef __APPLE__
#  define ftello64(x) ftello(x)
#elif defined _WIN32
#  define ftello64(x) _ftelli64(x)
#endif

void Usage()
{
    printf( "Usage: update [options] input.tracy output.tracy\n\n" );
    printf( "  -4: enable LZ4 compression\n" );
    printf( "  -h: enable LZ4HC compression\n" );
    printf( "  -e: enable extreme LZ4HC compression (very slow)\n" );
    printf( "  -z level: use Zstd compression with given compression level\n" );
    printf( "  -d: build dictionary for frame images\n" );
    printf( "  -s flags: strip selected data from capture:\n" );
    printf( "      l: locks, m: messages, p: plots, M: memory, i: frame images\n" );
    printf( "      c: context switches, s: sampling data, C: symbol code, S: source cache\n" );
    printf( "  -c: scan for source files missing in cache and add if found\n" );
    printf( "  -r: resolve symbols and patch callstack frames\n");
    printf( "  -p: substitute symbol resolution path with an alternative: \"REGEX_MATCH;REPLACEMENT\"\n");
    printf( "  -j: number of threads to use for compression (-1 to use all cores)\n" );

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

    tracy::FileCompression clev = tracy::FileCompression::Zstd;
    uint32_t events = tracy::EventType::All;
    int zstdLevel = 3;
    int streams = 4;
    bool buildDict = false;
    bool cacheSource = false;
    bool resolveSymbols = false;
    std::vector<std::string> pathSubstitutions;

    int c;
    while( ( c = getopt( argc, argv, "4hez:ds:crp:j:" ) ) != -1 )
    {
        switch( c )
        {
        case '4':
            clev = tracy::FileCompression::Fast;
            break;
        case 'h':
            clev = tracy::FileCompression::Slow;
            break;
        case 'e':
            clev = tracy::FileCompression::Extreme;
            break;
        case 'z':
            clev = tracy::FileCompression::Zstd;
            zstdLevel = atoi( optarg );
            if( zstdLevel > ZSTD_maxCLevel() || zstdLevel < ZSTD_minCLevel() )
            {
                printf( "Available Zstd compression levels range: %i - %i\n", ZSTD_minCLevel(), ZSTD_maxCLevel() );
                exit( 1 );
            }
            break;
        case 'd':
            buildDict = true;
            break;
        case 's':
        {
            auto ptr = optarg;
            do
            {
                switch( *optarg )
                {
                case 'l':
                    events &= ~tracy::EventType::Locks;
                    break;
                case 'm':
                    events &= ~tracy::EventType::Messages;
                    break;
                case 'p':
                    events &= ~tracy::EventType::Plots;
                    break;
                case 'M':
                    events &= ~tracy::EventType::Memory;
                    break;
                case 'i':
                    events &= ~tracy::EventType::FrameImages;
                    break;
                case 'c':
                    events &= ~tracy::EventType::ContextSwitches;
                    break;
                case 's':
                    events &= ~tracy::EventType::Samples;
                    break;
                case 'C':
                    events &= ~tracy::EventType::SymbolCode;
                    break;
                case 'S':
                    events &= ~tracy::EventType::SourceCache;
                    break;
                default:
                    Usage();
                    break;
                }
            }
            while( *++optarg != '\0' );
            break;
        }
        case 'c':
            cacheSource = true;
            break;
        case 'r':
            resolveSymbols = true;
            break;
        case 'p':
            pathSubstitutions.push_back(optarg);
            break;
        case 'j':
            streams = atoi( optarg );
            break;
        default:
            Usage();
            break;
        }
    }

    if (argc != optind + 2) Usage();

    const char* input = argv[optind];
    const char* output = argv[optind+1];

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
        int64_t tLoad, tSave;
        float ratio;
        int inVer;
        {
            const auto t0 = std::chrono::high_resolution_clock::now();
            const bool allowBgThreads = false;
            const bool allowStringModification = resolveSymbols;
            tracy::Worker worker( *f, (tracy::EventType::Type)events, allowBgThreads, allowStringModification );

#ifndef TRACY_NO_STATISTICS
            while( !worker.AreSourceLocationZonesReady() ) std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
#endif

            const auto t1 = std::chrono::high_resolution_clock::now();

            if( cacheSource ) worker.CacheSourceFiles();
            if( resolveSymbols ) PatchSymbols( worker, pathSubstitutions );

            auto w = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( output, clev, zstdLevel, streams ) );
            if( !w )
            {
                fprintf( stderr, "Cannot open output file!\n" );
                exit( 1 );
            }
            printf( "Saving... \r" );
            fflush( stdout );
            worker.Write( *w, buildDict );
            w->Finish();
            const auto t2 = std::chrono::high_resolution_clock::now();
            const auto stats = w->GetCompressionStatistics();
            ratio = 100.f * stats.second / stats.first;
            inVer = worker.GetTraceVersion();
            tLoad = std::chrono::duration_cast<std::chrono::nanoseconds>( t1 - t0 ).count();
            tSave = std::chrono::duration_cast<std::chrono::nanoseconds>( t2 - t1 ).count();
        }

        FILE* in = fopen( input, "rb" );
        fseek( in, 0, SEEK_END );
        const auto inSize = ftello64( in );
        fclose( in );

        FILE* out = fopen( output, "rb" );
        fseek( out, 0, SEEK_END );
        const auto outSize = ftello64( out );
        fclose( out );

        printf( "%s (%i.%i.%i) {%s} -> %s (%i.%i.%i) {%s, %.2f%%}  %s load, %s save, %.2f%% change\n",
            input, inVer >> 16, ( inVer >> 8 ) & 0xFF, inVer & 0xFF, tracy::MemSizeToString( inSize ),
            output, tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::MemSizeToString( outSize ), ratio,
            tracy::TimeToString( tLoad ), tracy::TimeToString( tSave ), float( outSize ) / inSize * 100 );
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
    catch( const tracy::FileReadError& e )
    {
        fprintf( stderr, "The file you are trying to open cannot be mapped to memory.\n" );
        exit( 1 );
    }
    catch( const tracy::LegacyVersion& e )
    {
        fprintf( stderr, "The file you are trying to open is from a legacy version.\n" );
        exit( 1 );
    }

    return 0;
}
