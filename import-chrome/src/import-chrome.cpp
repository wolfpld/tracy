#ifdef _WIN32
#  include <windows.h>
#endif

#include <fstream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "json.hpp"

#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyWorker.hpp"

using json = nlohmann::json;

void Usage()
{
    printf( "Usage: import-chrome input.json output.tracy\n\n" );
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

    if( argc != 3 ) Usage();

    const char* input = argv[1];
    const char* output = argv[2];

    printf( "Loading...\r" );
    fflush( stdout );

    std::ifstream is( input );
    if( !is.is_open() )
    {
        fprintf( stderr, "Cannot open input file!\n" );
        exit( 1 );
    }
    json j;
    is >> j;
    is.close();

    printf( "\33[2KParsing...\r" );
    fflush( stdout );

    std::vector<tracy::Worker::ImportEventTimeline> timeline;
    std::vector<tracy::Worker::ImportEventMessages> messages;

    if( j.is_object() && j.contains( "traceEvents" ) )
    {
        j = j["traceEvents"];
    }

    if( !j.is_array() )
    {
        fprintf( stderr, "Input must be either an array of events or an object containing an array of events under \"traceEvents\" key.\n" );
        exit( 1 );
    }

    for( auto& v : j )
    {
        const auto type = v["ph"].get<std::string>();
        if( type == "B" )
        {
            timeline.emplace_back( tracy::Worker::ImportEventTimeline {
                v["tid"].get<uint64_t>(),
                uint64_t( v["ts"].get<double>() * 1000. ),
                v["name"].get<std::string>(),
                false
            } );
        }
        else if( type == "E" )
        {
            timeline.emplace_back( tracy::Worker::ImportEventTimeline {
                v["tid"].get<uint64_t>(),
                uint64_t( v["ts"].get<double>() * 1000. ),
                "",
                true
            } );
        }
        else if( type == "X" )
        {
            const auto tid = v["tid"].get<uint64_t>();
            const auto ts0 = uint64_t( v["ts"].get<double>() * 1000. );
            const auto ts1 = v["dur"].is_object() ? ts0 + uint64_t( v["dur"].get<double>() * 1000. ) : ts0;
            const auto name = v["name"].get<std::string>();
            timeline.emplace_back( tracy::Worker::ImportEventTimeline { tid, ts0, name, false } );
            timeline.emplace_back( tracy::Worker::ImportEventTimeline { tid, ts1, "", true } );
        }
        else if( type == "i" || type == "I" )
        {
            messages.emplace_back( tracy::Worker::ImportEventMessages {
                v["tid"].get<uint64_t>(),
                uint64_t( v["ts"].get<double>() * 1000. ),
                v["name"].get<std::string>()
            } );
        }
    }

    std::stable_sort( timeline.begin(), timeline.end(), [] ( const auto& l, const auto& r ) { return l.timestamp < r.timestamp; } );
    std::stable_sort( messages.begin(), messages.end(), [] ( const auto& l, const auto& r ) { return l.timestamp < r.timestamp; } );

    uint64_t mts = 0;
    if( !timeline.empty() )
    {
        mts = timeline[0].timestamp;
    }
    if( !messages.empty() )
    {
        if( mts > messages[0].timestamp ) mts = messages[0].timestamp;
    }
    for( auto& v : timeline ) v.timestamp -= mts;
    for( auto& v : messages ) v.timestamp -= mts;

    printf( "\33[2KProcessing...\r" );
    fflush( stdout );

    auto program = input;
    while( *program ) program++;
    program--;
    while( program > input && ( *program != '/' || *program != '\\' ) ) program--;
    tracy::Worker worker( program, timeline, messages );

    auto w = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( output, clev ) );
    if( !w )
    {
        fprintf( stderr, "Cannot open output file!\n" );
        exit( 1 );
    }
    printf( "\33[2KSaving...\r" );
    fflush( stdout );
    worker.Write( *w );

    printf( "\33[2KCleanup...\n" );
    fflush( stdout );

    return 0;
}
