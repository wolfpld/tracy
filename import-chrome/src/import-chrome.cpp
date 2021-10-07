#ifdef _WIN32
#  include <windows.h>
#endif

#include <fstream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>

#include <sys/stat.h>

#ifdef _MSC_VER
#  define stat64 _stat64
#endif
#if defined __APPLE__
#  define stat64 stat
#endif

#include "json.hpp"

#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyMmap.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../zstd/zstd.h"

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

    json j;

    const auto fnsz = strlen( input );
    if( fnsz > 4 && memcmp( input+fnsz-4, ".zst", 4 ) == 0 )
    {
        FILE* f = fopen( input, "rb" );
        if( !f )
        {
            fprintf( stderr, "Cannot open input file!\n" );
            exit( 1 );
        }
        struct stat64 sb;
        if( stat64( input, &sb ) != 0 )
        {
            fprintf( stderr, "Cannot open input file!\n" );
            fclose( f );
            exit( 1 );
        }

        const auto zsz = sb.st_size;
        auto zbuf = (char*)mmap( nullptr, zsz, PROT_READ, MAP_SHARED, fileno( f ), 0 );
        fclose( f );
        if( !zbuf )
        {
            fprintf( stderr, "Cannot mmap input file!\n" );
            exit( 1 );
        }

        auto zctx = ZSTD_createDStream();
        ZSTD_initDStream( zctx );

        enum { tmpSize = 64*1024 };
        auto tmp = new char[tmpSize];

        ZSTD_inBuffer_s zin = { zbuf, (size_t)zsz };
        ZSTD_outBuffer_s zout = { tmp, (size_t)tmpSize };

        std::vector<uint8_t> buf;
        buf.reserve( 1024*1024 );

        while( zin.pos < zin.size )
        {
            const auto res = ZSTD_decompressStream( zctx, &zout, &zin );
            if( ZSTD_isError( res ) )
            {
                ZSTD_freeDStream( zctx );
                delete[] tmp;
                fprintf( stderr, "Couldn't decompress input file (%s)!\n", ZSTD_getErrorName( res ) );
                exit( 1 );
            }
            if( zout.pos > 0 )
            {
                const auto bsz = buf.size();
                buf.resize( bsz + zout.pos );
                memcpy( buf.data() + bsz, tmp, zout.pos );
                zout.pos = 0;
            }
        }

        ZSTD_freeDStream( zctx );
        delete[] tmp;
        munmap( zbuf, zsz );

        j = json::parse( buf.begin(), buf.end() );
    }
    else
    {
        std::ifstream is( input );
        if( !is.is_open() )
        {
            fprintf( stderr, "Cannot open input file!\n" );
            exit( 1 );
        }
        is >> j;
        is.close();
    }

    printf( "\33[2KParsing...\r" );
    fflush( stdout );

    // encode a pair of "real pid, real tid" from a trace into a
    // pseudo thread ID living in the single namespace of Tracy threads.
    struct PidTidEncoder
    {
        uint64_t tid;
        uint64_t pid;
        uint64_t pseudo_tid; // fake thread id, unique within Tracy
    };

    std::vector<PidTidEncoder> tid_encoders;
    std::vector<tracy::Worker::ImportEventTimeline> timeline;
    std::vector<tracy::Worker::ImportEventMessages> messages;
    std::vector<tracy::Worker::ImportEventPlots> plots;
    std::unordered_map<uint64_t, std::string> threadNames;

    const auto getPseudoTid = [&](json& val) -> uint64_t {
        const auto real_tid = val["tid"].get<uint64_t>();

        if( val.contains( "pid" ) )
        {
            // there might be multiple processes so we allocate a pseudo-tid
            // for each pair (pid, real_tid)
            const auto pid = val["pid"].get<uint64_t>();

            for ( auto &pair : tid_encoders)
            {
                if( pair.pid == pid && pair.tid == real_tid ) return pair.pseudo_tid;
            }

            assert( pid <= std::numeric_limits<uint32_t>::max() );
            assert( real_tid <= std::numeric_limits<uint32_t>::max() );

            const auto pseudo_tid = ( real_tid & 0xFFFFFFFF ) | ( pid << 32 );
            tid_encoders.emplace_back(PidTidEncoder {real_tid, pid, pseudo_tid});
            return pseudo_tid;
        }
        else
        {
            return real_tid;
        }
    };

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
        if( v.contains( "args" ) )
        {
            for( auto& kv : v["args"].items() )
            {
                const auto val = kv.value();
                const std::string s = val.is_string() ? val.get<std::string>() : val.dump();
                zoneText += kv.key() + ": " + s + "\n";
            }
        }

        std::string locFile;
        uint32_t locLine = 0;
        if( v.contains( "loc" ) )
        {
            auto loc = v["loc"].get<std::string>();
            const auto lpos = loc.find_last_of( ':' );
            if( lpos == std::string::npos )
            {
                std::swap( loc, locFile );
            }
            else
            {
                locFile = loc.substr( 0, lpos );
                locLine = atoi( loc.c_str() + lpos + 1 );
            }
        }

        if( type == "B" )
        {
            timeline.emplace_back( tracy::Worker::ImportEventTimeline {
                getPseudoTid(v),
                uint64_t( v["ts"].get<double>() * 1000. ),
                v["name"].get<std::string>(),
                std::move(zoneText),
                false,
                std::move(locFile),
                locLine
            } );
        }
        else if( type == "E" )
        {
            timeline.emplace_back( tracy::Worker::ImportEventTimeline {
                getPseudoTid(v),
                uint64_t( v["ts"].get<double>() * 1000. ),
                "",
                std::move(zoneText),
                true
            } );
        }
        else if( type == "X" )
        {
            const auto tid = getPseudoTid(v);
            const auto ts0 = uint64_t( v["ts"].get<double>() * 1000. );
            const auto ts1 = ts0 + uint64_t( v["dur"].get<double>() * 1000. );
            const auto name = v["name"].get<std::string>();
            timeline.emplace_back( tracy::Worker::ImportEventTimeline { tid, ts0, name, std::move(zoneText), false, std::move(locFile), locLine } );
            timeline.emplace_back( tracy::Worker::ImportEventTimeline { tid, ts1, "", "", true } );
        }
        else if( type == "i" || type == "I" )
        {
            messages.emplace_back( tracy::Worker::ImportEventMessages {
                getPseudoTid(v),
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
                const auto tid = getPseudoTid(v);
                threadNames[tid] = v["args"]["name"].get<std::string>();
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
    worker.Write( *w, false );

    printf( "\33[2KCleanup...\n" );
    fflush( stdout );

    return 0;
}
