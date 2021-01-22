#ifdef _WIN32
#  include <windows.h>
#endif

#include <fstream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unordered_map>

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
    std::vector<tracy::Worker::ImportEventPlots> plots;
    std::unordered_map<uint64_t, std::string> threadNames;

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

        std::string zoneText = "";
        if ( v.contains( "args" ) )
        {
            for ( auto& kv : v["args"].items() )
            {
                zoneText += kv.key() + ": " + kv.value().dump() + "\n";
            }
        }

        if( type == "B" )
        {
            timeline.emplace_back( tracy::Worker::ImportEventTimeline {
                v["tid"].get<uint64_t>(),
                uint64_t( v["ts"].get<double>() * 1000. ),
                v["name"].get<std::string>(),
                std::move(zoneText),
                false
            } );
        }
        else if( type == "E" )
        {
            timeline.emplace_back( tracy::Worker::ImportEventTimeline {
                v["tid"].get<uint64_t>(),
                uint64_t( v["ts"].get<double>() * 1000. ),
                "",
                std::move(zoneText),
                true
            } );
        }
        else if( type == "X" )
        {
            const auto tid = v["tid"].get<uint64_t>();
            const auto ts0 = uint64_t( v["ts"].get<double>() * 1000. );
            const auto ts1 = ts0 + uint64_t( v["dur"].get<double>() * 1000. );
            const auto name = v["name"].get<std::string>();
            timeline.emplace_back( tracy::Worker::ImportEventTimeline { tid, ts0, name, std::move(zoneText), false } );
            timeline.emplace_back( tracy::Worker::ImportEventTimeline { tid, ts1, "", "", true } );
        }
        else if( type == "i" || type == "I" )
        {
            messages.emplace_back( tracy::Worker::ImportEventMessages {
                v["tid"].get<uint64_t>(),
                uint64_t( v["ts"].get<double>() * 1000. ),
                v["name"].get<std::string>()
            } );
        }
        else if( type == "C" )
        {
            auto timestamp = int64_t( v["ts"].get<double>() * 1000 );
            for( auto& kv : v["args"].items() )
            {
                bool plotFound = false;
                auto& metricName = kv.key();
                auto dataPoint = std::make_pair( timestamp, kv.value().get<double>() );

                // The input file is assumed to have only very few metrics,
                // so iterating through plots is not a problem.
                for( auto& plot : plots )
                {
                    if( plot.name == metricName )
                    {
                        plot.data.emplace_back( dataPoint );
                        plotFound = true;
                        break;
                    }
                }
                if( !plotFound )
                {
                    auto formatting = tracy::PlotValueFormatting::Number;

                    // NOTE: With C++20 one could say metricName.ends_with( "_bytes" ) instead of rfind
                    auto metricNameLen = metricName.size();
                    if ( metricNameLen >= 6 && metricName.rfind( "_bytes" ) == metricNameLen - 6 ) {
                        formatting = tracy::PlotValueFormatting::Memory;
                    }

                    plots.emplace_back( tracy::Worker::ImportEventPlots {
                        std::move( metricName ),
                        formatting,
                        { dataPoint }
                    } );
                }
            }
        }
        else if (type == "M")
        {
            if (v.contains("name") && v["name"] == "thread_name" && v.contains("args") && v["args"].is_object() && v["args"].contains("name"))
            {
                threadNames[v["tid"].get<uint64_t>()] = v["args"]["name"].get<std::string>();
            }
        }
    }

    std::stable_sort( timeline.begin(), timeline.end(), [] ( const auto& l, const auto& r ) { return l.timestamp < r.timestamp; } );
    std::stable_sort( messages.begin(), messages.end(), [] ( const auto& l, const auto& r ) { return l.timestamp < r.timestamp; } );
    for( auto& v : plots ) std::stable_sort( v.data.begin(), v.data.end(), [] ( const auto& l, const auto& r ) { return l.first < r.first; } );

    uint64_t mts = 0;
    if( !timeline.empty() )
    {
        mts = timeline[0].timestamp;
    }
    if( !messages.empty() )
    {
        if( mts > messages[0].timestamp ) mts = messages[0].timestamp;
    }
    for( auto& plot : plots )
    {
        if( mts > plot.data[0].first ) mts = plot.data[0].first;
    }
    for( auto& v : timeline ) v.timestamp -= mts;
    for( auto& v : messages ) v.timestamp -= mts;
    for( auto& plot : plots )
    {
        for( auto& v : plot.data ) v.first -= mts;
    }

    printf( "\33[2KProcessing...\r" );
    fflush( stdout );

    auto&& getFilename = [](const char* in) {
        auto out = in;
        while (*out) ++out;
        --out;
        while (out > in && (*out != '/' || *out != '\\')) out--;
        return out;
    };

    tracy::Worker worker( getFilename(output), getFilename(input), timeline, messages, plots, threadNames );

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
