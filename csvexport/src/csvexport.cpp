#ifdef _WIN32
#  include <windows.h>
#endif

#include <algorithm>
#include <map>
#include <sstream>
#include <string>

#include <assert.h>
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../getopt/getopt.h"
#include "../../public/common/TracyVersion.hpp"
#include "GitRef.hpp"

static void print_usage_exit( int e )
{
    fprintf( stderr, "tracy-csvexport %i.%i.%i / %s\n\n", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
    fprintf( stderr, "Extract statistics from a trace to a CSV format\n" );
    fprintf( stderr, "Usage:\n" );
    fprintf( stderr, "  extract [OPTION...] <trace file>\n" );
    fprintf( stderr, "\n" );
    fprintf( stderr, "  -h, --help                 Print usage\n" );
    fprintf( stderr, "  -V, --version              Show version information\n" );
    fprintf( stderr, "  -f, --filter arg           Filter zone names (default: "
                     ")\n" );
    fprintf( stderr, "  -F, --frames               Report frame statistics, one row per frame set\n" );
    fprintf( stderr, "  -S, --sections             Add per-section frame statistics (only with -F)\n" );
    fprintf( stderr, "  -s, --sep arg              CSV separator (default: ,)\n" );
    fprintf( stderr, "  -c, --case                 Case sensitive filtering\n" );
    fprintf( stderr, "  -e, --self                 Get self times\n" );
    fprintf( stderr, "  -u, --unwrap               Report each cpu zone event\n" );
    fprintf( stderr, "  -g, --gpu                  Report each gpu zone event\n" );
    fprintf( stderr, "  -m, --messages             Report only messages\n" );
    fprintf( stderr, "  -p, --plot                 Report plot data (only with -u)\n" );
    fprintf( stderr, "  -t, --truncated_mean[=arg] Report truncated mean (arg is the percentile. Default is 90)\n" );

    exit( e );
}

struct Args
{
    const char* filter;
    const char* separator;
    const char* trace_file;
    bool case_sensitive;
    bool self_time;
    bool unwrap;
    bool show_gpu;
    bool unwrapMessages;
    bool plot;
    bool frames;
    bool sections;
    int truncated_mean_percentile;
};

static Args parse_args( int argc, char** argv )
{
    if( argc == 1 ) print_usage_exit( 1 );

    Args args = { "", ",", "", false, false, false, false, false, false, false, false, 0 };

    struct option long_opts[] = {
        { "help", no_argument, nullptr, 'h' },
        { "version", no_argument, nullptr, 'V' },
        { "filter", required_argument, nullptr, 'f' },
        { "frames", no_argument, nullptr, 'F' },
        { "sections", no_argument, nullptr, 'S' },
        { "sep", required_argument, nullptr, 's' },
        { "case", no_argument, nullptr, 'c' },
        { "self", no_argument, nullptr, 'e' },
        { "unwrap", no_argument, nullptr, 'u' },
        { "gpu", no_argument, nullptr, 'g' },
        { "messages", no_argument, nullptr, 'm' },
        { "plot", no_argument, nullptr, 'p' },
        { "truncated_mean", optional_argument, nullptr, 't' },
        { nullptr, 0, nullptr, 0 }
    };

    int c;
    while( ( c = getopt_long( argc, argv, "hf:FSs:t:ceugmpV", long_opts, nullptr ) ) != -1 )
    {
        switch( c )
        {
        case 'h':
            print_usage_exit( 0 );
            break;
        case 'V':
            printf( "tracy-csvexport %i.%i.%i / %s\n", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
            exit( 0 );
        case 'f':
            args.filter = optarg;
            break;
        case 'F':
            args.frames = true;
            break;
        case 'S':
            args.sections = true;
            break;
        case 's':
            args.separator = optarg;
            break;
        case 'c':
            args.case_sensitive = true;
            break;
        case 'e':
            args.self_time = true;
            break;
        case 'u':
            args.unwrap = true;
            break;
        case 'g':
            args.show_gpu = true;
            break;
        case 'm':
            args.unwrapMessages = true;
            break;
        case 'p':
            args.plot = true;
            break;
        case 't':
            args.truncated_mean_percentile = std::clamp<int>( optarg ? atoi( optarg ) : 90, 1, 99 );
            break;
        default:
            print_usage_exit( 1 );
            break;
        }
    }

    if( argc != optind + 1 )
    {
        print_usage_exit( 1 );
    }

    args.trace_file = argv[optind];

    return args;
}

static bool is_substring( const char* term, const char* s, bool case_sensitive = false )
{
    auto new_term = std::string( term );
    auto new_s = std::string( s );

    if( !case_sensitive )
    {
        std::ranges::transform( new_term, new_term.begin(), []( unsigned char c ) { return tolower( c ); } );
        std::ranges::transform( new_s, new_s.begin(), []( unsigned char c ) { return tolower( c ); } );
    }

    return new_s.find( new_term ) != std::string::npos;
}

static const char* get_name( int32_t id, const tracy::Worker& worker )
{
    auto& srcloc = worker.GetSourceLocation( id );
    return worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
}

template<typename T>
static std::string join( const T& v, const char* sep )
{
    std::ostringstream s;
    for( const auto& i : v )
    {
        if( &i != &v[0] )
        {
            s << sep;
        }
        s << i;
    }
    return s.str();
}

// Returns {pN, truncated_mean}
static std::pair<int64_t, int64_t> percentile_and_truncated_mean( std::vector<int64_t>& data, const double p )
{
    assert( p >= 0.0 && p <= 1.0 );

    if( data.empty() ) return { 0, 0 };
    std::ranges::sort( data );

    const std::size_t n = data.size();
    const double idx = p * ( static_cast<double>( n ) - 1.0 );
    const std::size_t idxLow = static_cast<std::size_t>( floor( idx ) );
    const std::size_t idxHigh = std::min( idxLow + 1, n - 1 );
    const double frac = idx - static_cast<double>( idxLow );

    const double low = static_cast<double>( data[idxLow] );
    const double high = static_cast<double>( data[idxHigh] );

    // percentile value
    const double pval_double = low + ( high - low ) * frac;
    const int64_t pval_int = static_cast<int64_t>( llround( pval_double ) );

    // Compute truncated mean: average of all values <= pval_double
    int64_t sum = 0;
    std::size_t count = 0;
    for( std::size_t i = 0; i < n; ++i )
    {
        if( static_cast<double>( data[i] ) <= pval_double )
        {
            sum += data[i];
            ++count;
        }
        else
        {
            break; // sorted, so we can stop once we hit > pval_double
        }
    }

    if( count == 0 )
    {
        // should not happen for p in [0,1] unless data empty, but keep defensive behaviour
        return { pval_int, 0 };
    }

    const int64_t truncated_mean = sum / count;
    return { pval_int, truncated_mean };
}

// From TracyView.cpp
static int64_t GetZoneChildTimeFast( const tracy::Worker& worker, const tracy::ZoneEvent& zone )
{
    int64_t time = 0;
    if( zone.HasChildren() )
    {
        auto& children = worker.GetZoneChildren( zone.Child() );
        if( children.is_magic() )
        {
            auto& vec = *(tracy::Vector<tracy::ZoneEvent>*)&children;
            for( auto& v : vec )
            {
                assert( v.IsEndValid() );
                time += v.End() - v.Start();
            }
        }
        else
        {
            for( auto& v : children )
            {
                assert( v->IsEndValid() );
                time += v->End() - v->Start();
            }
        }
    }
    return time;
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

    Args args = parse_args( argc, argv );

    auto f = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( args.trace_file ) );
    if( !f )
    {
        fprintf( stderr, "Could not open file %s\n", args.trace_file );
        return 1;
    }

    auto worker = tracy::Worker( *f );

    if( args.unwrapMessages )
    {
        const auto& msgs = worker.GetMessages();

        if( !msgs.empty() )
        {
            std::vector<const char*> columnsForMessages {
                "MessageName",
                "total_ns"
            };
            std::string headerForMessages = join( columnsForMessages, args.separator );
            printf( "%s\n", headerForMessages.data() );

            for( auto& it : msgs )
            {
                std::vector<std::string> values( columnsForMessages.size() );

                values[0] = worker.GetString( it->ref );
                values[1] = std::to_string( it->time );

                std::string row = join( values, args.separator );
                printf( "%s\n", row.data() );
            }
        }
        else
        {
            printf( "There are currently no messages!\n" );
        }

        return 0;
    }

    while( !worker.AreSourceLocationZonesReady() )
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
    }

    if( args.frames )
    {
        // The base frame set always holds two bootstrap events; the profiler
        // only considers frames present past that point.
        if( !worker.AreFramesUsed() )
        {
            printf( "There are currently no frames!\n" );
            return 0;
        }

        const auto& frames = worker.GetFrames();
        const auto span = worker.GetLastTime();

        // Sections aggregated by name; open sections reach the end of the trace, as in the UI.
        std::map<std::string, std::vector<std::pair<int64_t, int64_t>>> sections;
        if( args.sections )
        {
            for( const auto& s : worker.GetSections() )
            {
                for( const auto& v : s.second )
                {
                    if( !v.text.Active() ) continue;
                    sections[worker.GetString( v.text )].emplace_back( v.start.Val(), v.end.IsNonNegative() ? v.end.Val() : span );
                }
            }
        }

        std::vector<const char*> columns { "frame_set" };
        if( args.sections )
        {
            columns.push_back( "section" );
            columns.push_back( "instances" );
        }
        columns.insert( columns.end(), {
            "continuous",
            "frames",
            "counts",
            "total_ns",
            "span_perc",
            "min_ns",
            "max_ns",
            "mean_ns",
            "median_ns",
            "std_ns",
            "cv_perc",
            "p75_ns",
            "p90_ns",
            "p99_ns",
            "p99_9_ns"
        } );

        std::string header = join( columns, args.separator );
        printf( "%s\n", header.data() );

        const auto PrintStats = [&]( const char* setName, const char* section, size_t instances, bool continuous, size_t fsz, std::vector<int64_t>& times )
        {
            const auto vsz = times.size();
            if( vsz == 0 ) return;
            std::ranges::sort( times );

            int64_t total = 0;
            double sumSq = 0;
            for( const auto t : times )
            {
                total += t;
                sumSq += double( t ) * t;
            }

            // Same definitions as the profiler's Frame statistics window: nearest-rank
            // percentiles and sample (n-1) standard deviation.
            const auto Percentile = [&times, vsz]( double p ) { return times[std::min( vsz - 1, size_t( p * vsz ) )]; };
            const double avg = double( total ) / vsz;
            double sd = 0;
            if( vsz > 1 ) sd = sqrt( ( sumSq - 2. * double( total ) * avg + avg * avg * vsz ) / ( vsz - 1 ) );

            std::vector<std::string> values;
            values.reserve( columns.size() );
            values.emplace_back( setName );
            if( args.sections )
            {
                values.emplace_back( section );
                values.emplace_back( std::to_string( instances ) );
            }
            values.emplace_back( continuous ? "1" : "0" );
            values.emplace_back( std::to_string( fsz ) );
            values.emplace_back( std::to_string( vsz ) );
            values.emplace_back( std::to_string( total ) );
            values.emplace_back( span > 0 ? std::to_string( 100. * total / span ) : "0" );
            values.emplace_back( std::to_string( times.front() ) );
            values.emplace_back( std::to_string( times.back() ) );
            values.emplace_back( std::to_string( avg ) );
            values.emplace_back( std::to_string( Percentile( 0.5 ) ) );
            values.emplace_back( std::to_string( sd ) );
            values.emplace_back( std::to_string( 100. * sd / avg ) );
            values.emplace_back( std::to_string( Percentile( 0.75 ) ) );
            values.emplace_back( std::to_string( Percentile( 0.9 ) ) );
            values.emplace_back( std::to_string( Percentile( 0.99 ) ) );
            values.emplace_back( std::to_string( Percentile( 0.999 ) ) );

            std::string row = join( values, args.separator );
            printf( "%s\n", row.data() );
        };

        for( const auto& fd : frames )
        {
            const auto fsz = worker.GetFullFrameCount( *fd );
            const auto setName = worker.GetString( fd->name );

            std::vector<int64_t> times;
            times.reserve( fsz );
            for( size_t i=0; i<fsz; i++ )
            {
                const auto t = worker.GetFrameTime( *fd, i );
                if( t > 0 ) times.push_back( t );
            }
            PrintStats( setName, "", 0, fd->continuous, fsz, times );

            for( const auto& s : sections )
            {
                std::vector<std::pair<int, int>> ranges;
                ranges.reserve( s.second.size() );
                for( const auto& r : s.second )
                {
                    const auto fr = worker.GetFrameRange( *fd, r.first, r.second );
                    if( fr.second > fr.first ) ranges.emplace_back( fr );
                }
                std::ranges::sort( ranges );

                // Overlapping instances share frames, so merge the index ranges before collection.
                times.clear();
                const auto Collect = [&]( int f, int l )
                {
                    for( int i=f; i<l; i++ )
                    {
                        const auto t = worker.GetFrameTime( *fd, i );
                        if( t > 0 ) times.push_back( t );
                    }
                };
                int first = -1, last = -1;
                for( const auto& r : ranges )
                {
                    if( first < 0 )
                    {
                        first = r.first;
                        last = r.second;
                    }
                    else if( r.first <= last )
                    {
                        last = std::max( last, r.second );
                    }
                    else
                    {
                        Collect( first, last );
                        first = r.first;
                        last = r.second;
                    }
                }
                if( first >= 0 ) Collect( first, last );

                PrintStats( setName, s.first.c_str(), s.second.size(), fd->continuous, fsz, times );
            }
        }
        return 0;
    }

    if( args.show_gpu )
    {
        auto& gpu_slz = worker.GetGpuSourceLocationZones();
        tracy::Vector<decltype( gpu_slz.begin() )> gpu_slz_selected;
        gpu_slz_selected.reserve( gpu_slz.size() );

        uint32_t total_cnt = 0;
        for( auto it = gpu_slz.begin(); it != gpu_slz.end(); ++it )
        {
            if( it->second.total != 0 )
            {
                ++total_cnt;
                if( args.filter[0] == '\0' )
                {
                    gpu_slz_selected.push_back_no_space_check( it );
                }
                else
                {
                    auto name = get_name( it->first, worker );
                    if( is_substring( args.filter, name, args.case_sensitive ) )
                    {
                        gpu_slz_selected.push_back_no_space_check( it );
                    }
                }
            }
        }

        std::vector<const char*> columns {
            "name",
            "src_file",
            "Time from start of program",
            "GPU execution time"
        };

        std::string header = join( columns, args.separator );
        printf( "%s\n", header.data() );

        const auto last_time = worker.GetLastTime();
        for( auto& it : gpu_slz_selected )
        {
            std::vector<std::string> values( columns.size() );

            values[0] = get_name( it->first, worker );

            const auto& srcloc = worker.GetSourceLocation( it->first );
            values[1] = worker.GetString( srcloc.file );

            const auto& zone_data = it->second;
            for( const auto& zone_thread_data : zone_data.zones )
            {
                tracy::GpuEvent* gpu_event = zone_thread_data.Zone();
                const auto start = gpu_event->GpuStart();
                const auto end = gpu_event->GpuEnd();

                values[2] = std::to_string( start );

                auto timespan = end - start;
                values[3] = std::to_string( timespan );

                std::string row = join( values, args.separator );
                printf( "%s\n", row.data() );
            }
        }
        return 0;
    }

    auto& slz = worker.GetSourceLocationZones();
    tracy::Vector<decltype( slz.begin() )> slz_selected;
    slz_selected.reserve( slz.size() );

    uint32_t total_cnt = 0;
    for( auto it = slz.begin(); it != slz.end(); ++it )
    {
        if( it->second.total != 0 )
        {
            ++total_cnt;
            if( args.filter[0] == '\0' )
            {
                slz_selected.push_back_no_space_check( it );
            }
            else
            {
                auto name = get_name( it->first, worker );
                if( is_substring( args.filter, name, args.case_sensitive ) )
                {
                    slz_selected.push_back_no_space_check( it );
                }
            }
        }
    }

    std::vector<const char*> columns;
    if( args.unwrap )
    {
        columns = { "name", "src_file", "src_line", "ns_since_start", "exec_time_ns", "thread", "value" };
    }
    else
    {
        columns = { "name", "src_file", "src_line", "total_ns", "total_perc", "counts", "mean_ns", "min_ns", "max_ns", "std_ns" };

        if( args.truncated_mean_percentile )
        {
            columns.push_back( "percentile_ns" );
            columns.push_back( "truncated_mean_ns" );
        }
    }
    std::string header = join( columns, args.separator );
    printf( "%s\n", header.data() );

    const auto last_time = worker.GetLastTime();
    for( auto& it : slz_selected )
    {
        std::vector<std::string> values( columns.size() );

        values[0] = get_name( it->first, worker );

        const auto& srcloc = worker.GetSourceLocation( it->first );
        values[1] = worker.GetString( srcloc.file );
        values[2] = std::to_string( srcloc.line );

        const auto& zone_data = it->second;

        if( args.unwrap )
        {
            int i = 0;
            for( const auto& zone_thread_data : zone_data.zones )
            {
                const auto zone_event = zone_thread_data.Zone();
                const auto tId = zone_thread_data.Thread();
                const auto start = zone_event->Start();
                const auto end = zone_event->End();

                values[3] = std::to_string( start );

                auto timespan = end - start;
                if( args.self_time )
                {
                    timespan -= GetZoneChildTimeFast( worker, *zone_event );
                }
                values[4] = std::to_string( timespan );
                values[5] = std::to_string( tId );
                if( worker.HasZoneExtra( *zone_event ) )
                {
                    const auto& text = worker.GetZoneExtra( *zone_event ).text;
                    if( text.Active() )
                    {
                        values[6] = worker.GetString( text );
                    }
                }

                std::string row = join( values, args.separator );
                printf( "%s\n", row.data() );
            }
        }
        else
        {
            const auto time = args.self_time ? zone_data.selfTotal : zone_data.total;
            values[3] = std::to_string( time );
            values[4] = std::to_string( 100. * time / last_time );

            const auto sz = zone_data.zones.size();
            values[5] = std::to_string( sz );

            const auto avg = time / sz;

            values[6] = std::to_string( avg );

            const auto tmin = args.self_time ? zone_data.selfMin : zone_data.min;
            const auto tmax = args.self_time ? zone_data.selfMax : zone_data.max;
            values[7] = std::to_string( tmin );
            values[8] = std::to_string( tmax );

            const auto ss = zone_data.sumSq - 2. * zone_data.total * avg + avg * avg * sz;
            double std = 0;
            if( sz > 1 ) std = sqrt( ss / ( sz - 1 ) );
            values[9] = std::to_string( std );

            if( args.truncated_mean_percentile )
            {
                std::vector<int64_t> samples;
                samples.reserve( zone_data.zones.size() );
                for( const auto& zone_thread_data : zone_data.zones )
                {
                    const auto zone_event = zone_thread_data.Zone();
                    auto timespan = zone_event->End() - zone_event->Start();
                    if( args.self_time ) timespan -= GetZoneChildTimeFast( worker, *zone_event );
                    samples.push_back( timespan );
                }

                std::pair<int64_t, int64_t> pN = percentile_and_truncated_mean( samples, args.truncated_mean_percentile / 100.0 );
                values[10] = std::to_string( pN.first );
                values[11] = std::to_string( pN.second );
            }

            std::string row = join( values, args.separator );
            printf( "%s\n", row.data() );
        }
    }

    if( args.plot && args.unwrap )
    {
        while( !worker.IsBackgroundDone() ) std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
        std::lock_guard lock( worker.GetDataLock() );
        auto& plots = worker.GetPlots();
        for( const auto& plot : plots )
        {
            std::vector<std::string> values( columns.size() );
            values[0] = worker.GetString( plot->name );

            for( const auto& val : plot->data )
            {
                if( args.unwrap )
                {
                    values[3] = std::to_string( val.time.Val() );
                    values[6] = std::to_string( val.val );
                }
                std::string row = join( values, args.separator );
                printf( "%s\n", row.data() );
            }
        }
    }

    return 0;
}
