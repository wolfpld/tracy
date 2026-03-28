#include "TracyFileRead.hpp"
#include "TracyFileWrite.hpp"
#include "TracyPrint.hpp"
#include "TracyWorker.hpp"
#include "../../getopt/getopt.h"
#include "../../public/common/TracyVersion.hpp"
#include "GitRef.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

template<typename T1, typename T2>
struct PairHash
{
    size_t operator()( std::pair<T1, T2> const& p ) const
    {
        auto h1 = std::hash<T1>{}( p.first );
        auto h2 = std::hash<T2>{}( p.second );
        return h1 ^ (h2 << 1);
    }
};

using namespace std::chrono_literals;

struct ExportedTrace
{
    uint64_t pid = 0;
    std::string process;
    std::string name;
    std::vector<tracy::Worker::ImportEventTimeline> timeline;
    std::vector<tracy::Worker::ImportEventMessages> messages;
    std::vector<tracy::Worker::ImportEventPlots> plots;
    std::unordered_map<uint64_t, std::string> threadNames;

    static bool orderTimeline( tracy::Worker::ImportEventTimeline const& a, tracy::Worker::ImportEventTimeline const& b )
    {
        return a.timestamp < b.timestamp;
    }

    static bool orderMessages( tracy::Worker::ImportEventMessages const& a, tracy::Worker::ImportEventMessages const& b )
    {
        return a.timestamp < b.timestamp;
    }

    static std::optional<ExportedTrace> fromFile( std::string const& filepath, size_t fileIndex )
    {
        auto sourceFile = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( filepath.c_str() ) );
        if( !sourceFile )
        {
            std::cerr << "Could not open file: " << filepath << std::endl;
            return std::nullopt;
        }

        std::cout << "Reading: " << filepath << std::endl;

        tracy::Worker worker( *sourceFile, tracy::EventType::All, true, false );
        while( !worker.AreSourceLocationZonesReady() )
        {
            std::this_thread::sleep_for( 1s );
        }

        ExportedTrace trace;
        trace.pid = worker.GetPid();
        if( trace.pid == 0 )
        {
            trace.pid = 0xFFFE0000 | fileIndex;
        }
        trace.process = worker.GetCaptureProgram();
        if( trace.process.empty() )
        {
            trace.process = "unknown";
        }
        trace.name = worker.GetCaptureName();

        std::cout << "  PID: " << trace.pid << ", Process: " << trace.process << std::endl;

        std::unordered_set<uint64_t> seenThreads;

        auto& sourceLocationZones = worker.GetSourceLocationZones();
        std::cout << "  Zones: " << sourceLocationZones.size() << std::endl;
        for( auto& zone_it : sourceLocationZones )
        {
            const tracy::SourceLocation& srcLoc = worker.GetSourceLocation( zone_it.first );
            std::string zoneFile = worker.GetString( srcLoc.file );
            int zoneLine = srcLoc.line;
            std::string zoneName = worker.GetZoneName( srcLoc );

            for( auto& zoneData : zone_it.second.zones )
            {
                const auto zone = zoneData.Zone();
                const uint64_t threadId = worker.DecompressThread( zoneData.Thread() );
                seenThreads.insert( threadId );

                auto& startEvent = trace.timeline.emplace_back();
                startEvent.locFile = zoneFile;
                startEvent.locLine = zoneLine;
                startEvent.name = zoneName;
                startEvent.tid = threadId;
                startEvent.isEnd = false;
                startEvent.timestamp = zone->Start();

                auto& endEvent = trace.timeline.emplace_back();
                endEvent.locFile = zoneFile;
                endEvent.locLine = zoneLine;
                endEvent.name = zoneName;
                endEvent.tid = threadId;
                endEvent.isEnd = true;
                endEvent.timestamp = zone->End();
            }
        }
        std::sort( trace.timeline.begin(), trace.timeline.end(), orderTimeline );

        auto& messages = worker.GetMessages();
        std::cout << "  Messages: " << messages.size() << std::endl;
        for( auto& msg : messages )
        {
            auto& importMsg = trace.messages.emplace_back();
            importMsg.tid = worker.DecompressThread( msg->thread );
            importMsg.message = worker.GetString( msg->ref );
            importMsg.timestamp = msg->time;
            seenThreads.insert( importMsg.tid );
        }
        std::sort( trace.messages.begin(), trace.messages.end(), orderMessages );

        auto& plots = worker.GetPlots();
        std::cout << "  Plots: " << plots.size() << std::endl;
        for( auto& plot : plots )
        {
            auto& importPlot = trace.plots.emplace_back();
            importPlot.name = worker.GetString( plot->name );
            importPlot.format = plot->format;
            importPlot.data.reserve( plot->data.size() );
            for( auto& pt : plot->data )
            {
                importPlot.data.emplace_back( pt.time.Val(), pt.val );
            }
        }

        for( uint64_t tid : seenThreads )
        {
            std::string name = worker.GetThreadName( tid );
            trace.threadNames[tid] = name.empty() ? std::to_string( tid ) : name;
        }

        return trace;
    }
};

struct MergedTrace
{
    std::vector<tracy::Worker::ImportEventTimeline> timeline;
    std::vector<tracy::Worker::ImportEventMessages> messages;
    std::vector<tracy::Worker::ImportEventPlots> plots;
    std::unordered_map<uint64_t, std::string> threadNames;
    std::string name;
    std::string process;

    static MergedTrace merge( std::vector<ExportedTrace> const& traces )
    {
        MergedTrace out;

        if( traces.empty() ) return out;

        out.name = traces[0].name;
        out.process = traces[0].process + " (merged)";

        std::unordered_map<std::pair<std::string, std::string>, size_t, PairHash<std::string, std::string>> nameCounts;
        for( auto const& trace : traces )
        {
            for( auto const& [tid, threadName] : trace.threadNames )
            {
                auto key = std::make_pair( trace.process, threadName );
                nameCounts[key]++;
            }
        }

        std::unordered_map<std::pair<std::string, std::string>, size_t, PairHash<std::string, std::string>> plotNameCounts;
        for( auto const& trace : traces )
        {
            for( auto const& plot : trace.plots )
            {
                auto key = std::make_pair( trace.process, plot.name );
                plotNameCounts[key]++;
            }
        }

        std::unordered_map<std::pair<uint64_t, uint64_t>, uint64_t, PairHash<uint64_t, uint64_t>> tidMapping;

        size_t totalTimeline = 0, totalMessages = 0, totalPlots = 0;
        for( auto const& trace : traces )
        {
            totalTimeline += trace.timeline.size();
            totalMessages += trace.messages.size();
            totalPlots += trace.plots.size();
        }
        out.timeline.reserve( totalTimeline );
        out.messages.reserve( totalMessages );
        out.plots.reserve( totalPlots );

        for( auto const& trace : traces )
        {
            for( auto const& [origTid, threadName] : trace.threadNames )
            {
                uint64_t encodedTid = (origTid & 0xFFFFFFFF) | (trace.pid << 32);

                auto [it, inserted] = tidMapping.emplace( std::make_pair( trace.pid, origTid ), encodedTid );
                uint64_t finalTid = it->second;

                auto key = std::make_pair( trace.process, threadName );
                std::string displayName;
                if( nameCounts[key] > 1 )
                {
                    displayName = trace.process + "[" + std::to_string( trace.pid ) + "]/" + threadName;
                }
                else
                {
                    displayName = trace.process + "/" + threadName;
                }
                out.threadNames[finalTid] = displayName;
            }

            for( auto const& event : trace.timeline )
            {
                auto& inserted = out.timeline.emplace_back( event );
                auto key = std::make_pair( trace.pid, event.tid );
                auto it = tidMapping.find( key );
                if( it != tidMapping.end() )
                {
                    inserted.tid = it->second;
                }
            }

            for( auto const& msg : trace.messages )
            {
                auto& inserted = out.messages.emplace_back( msg );
                auto key = std::make_pair( trace.pid, msg.tid );
                auto it = tidMapping.find( key );
                if( it != tidMapping.end() )
                {
                    inserted.tid = it->second;
                }
            }

            for( auto const& plot : trace.plots )
            {
                auto renamedPlot = plot;
                auto key = std::make_pair( trace.process, plot.name );
                if( plotNameCounts[key] > 1 )
                {
                    renamedPlot.name = trace.process + "[" + std::to_string( trace.pid ) + "]/" + plot.name;
                }
                else
                {
                    renamedPlot.name = trace.process + "/" + plot.name;
                }
                out.plots.push_back( renamedPlot );
            }
        }

        std::sort( out.timeline.begin(), out.timeline.end(), ExportedTrace::orderTimeline );
        std::sort( out.messages.begin(), out.messages.end(), ExportedTrace::orderMessages );

        return out;
    }
};

[[noreturn]] void Usage()
{
    printf( "tracy-merge %i.%i.%i / %s\n\n", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
    printf( "Usage: tracy-merge -o output.tracy input1.tracy [input2.tracy ...]\n\n" );
    printf( "Options:\n" );
    printf( "  -o, --output <file>    Output file path (required)\n" );
    printf( "  -f, --force            Overwrite output file if it exists\n" );
    printf( "  -h, --help             Show this help message\n" );
    printf( "  -V, --version          Show version information\n" );
    exit( 1 );
}

int main( int argc, char** argv )
{
    std::string outputFile;
    std::vector<std::string> inputFiles;
    bool overwrite = false;

    static struct option longOptions[] = {
        { "output", required_argument, nullptr, 'o' },
        { "force", no_argument, nullptr, 'f' },
        { "help", no_argument, nullptr, 'h' },
        { "version", no_argument, nullptr, 'V' },
        { nullptr, 0, nullptr, 0 }
    };

    int c;
    while( ( c = getopt_long( argc, argv, "o:fhV", longOptions, nullptr ) ) != -1 )
    {
        switch( c )
        {
        case 'o':
            outputFile = optarg;
            break;
        case 'f':
            overwrite = true;
            break;
        case 'h':
            Usage();
            break;
        case 'V':
            printf( "tracy-merge %i.%i.%i / %s\n", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
            exit( 0 );
        default:
            Usage();
            break;
        }
    }

    if( outputFile.empty() )
    {
        std::cerr << "Error: Output file is required (-o)" << std::endl << std::endl;
        Usage();
    }

    while( optind < argc )
    {
        inputFiles.emplace_back( argv[optind++] );
    }

    if( inputFiles.empty() )
    {
        std::cerr << "Error: At least one input file is required" << std::endl << std::endl;
        Usage();
    }

    if( std::filesystem::exists( outputFile ) )
    {
        if( overwrite )
        {
            std::filesystem::remove( outputFile );
        }
        else
        {
            std::cerr << "Error: Output file already exists: " << outputFile << std::endl;
            std::cerr << "Use -f to overwrite" << std::endl;
            return 1;
        }
    }

    std::vector<ExportedTrace> traces;
    traces.reserve( inputFiles.size() );

    for( size_t i = 0; i < inputFiles.size(); i++ )
    {
        auto trace = ExportedTrace::fromFile( inputFiles[i], i );
        if( !trace )
        {
            std::cerr << "Failed to read: " << inputFiles[i] << std::endl;
            return 1;
        }
        traces.push_back( std::move( *trace ) );
    }

    std::cout << "\nMerging " << traces.size() << " trace(s)..." << std::endl;
    MergedTrace merged = MergedTrace::merge( traces );

    std::cout << "  Total zones: " << merged.timeline.size() << std::endl;
    std::cout << "  Total messages: " << merged.messages.size() << std::endl;
    std::cout << "  Total threads: " << merged.threadNames.size() << std::endl;

    auto outFile = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( outputFile.c_str(), tracy::FileCompression::Zstd, 3, 4 ) );
    if( !outFile )
    {
        std::cerr << "Error: Could not open output file: " << outputFile << std::endl;
        return 1;
    }

    std::cout << "Writing: " << outputFile << std::endl;
    tracy::Worker writer( merged.name.c_str(), merged.process.c_str(), merged.timeline, merged.messages, merged.plots, merged.threadNames );
    writer.Write( *outFile, false );
    outFile->Finish();

    auto stats = outFile->GetCompressionStatistics();
    std::cout << "Done. Output size: " << tracy::MemSizeToString( stats.second ) << " (" << (100.0 * stats.second / stats.first) << "% ratio)" << std::endl;

    return 0;
}
