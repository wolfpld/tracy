#ifdef _WIN32
#  include <windows.h>
#endif

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <math.h>
#include <stdio.h>
#include <stdint.h>

#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../getopt/getopt.h"

void print_usage_exit(int e)
{
    fprintf(stderr, "Extract statistics from a trace to a CSV format\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  extract [OPTION...] <trace file>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -h, --help               Print usage\n");
    fprintf(stderr, "  -f, --filter arg         Filter zone names (default: "")\n");
    fprintf(stderr, "  -s, --sep arg            CSV separator (default: ,)\n");
    fprintf(stderr, "  -c, --case               Case sensitive filtering\n");
    fprintf(stderr, "  -e, --self               Get self times\n");
    fprintf(stderr, "  -u, --unwrap             Report each cpu zone event\n");
    fprintf(stderr, "  -g, --gpu                Report each gpu zone event\n" );
    fprintf(stderr, "  -m, --messages           Report only messages\n");
    fprintf(stderr, "  -p, --plot               Report plot data (only with -u)\n");
    fprintf(stderr, "  -t, --truncated_mean arg Report truncated mean (arg is the percentile. Default is 90)\n");

    exit(e);
}

struct Args {
    const char* filter;
    const char* separator;
    const char* trace_file;
    bool case_sensitive;
    bool self_time;
    bool unwrap;
    bool show_gpu;
    bool unwrapMessages;
    bool plot;
    int truncated_mean_percentile;
};

Args parse_args(int argc, char** argv)
{
    if (argc == 1)
    {
        print_usage_exit(1);
    }

    Args args = { "", ",", "", false, false, false, false, false, false, 0};

    struct option long_opts[] = {
        { "help", no_argument, NULL, 'h' },
        { "filter", optional_argument, NULL, 'f' },
        { "sep", optional_argument, NULL, 's' },
        { "case", no_argument, NULL, 'c' },
        { "self", no_argument, NULL, 'e' },
        { "unwrap", no_argument, NULL, 'u' },
        { "gpu", no_argument, NULL, 'g' },
        { "messages", no_argument, NULL, 'm' },
        { "plot", no_argument, NULL, 'p' },
        { "truncated_mean", optional_argument, NULL, 't' },
        { NULL, 0, NULL, 0 }
    };

    int c;
    while ((c = getopt_long(argc, argv, "hf:s:ceugmp", long_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'h':
            print_usage_exit(0);
            break;
        case 'f':
            args.filter = optarg;
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
            args.truncated_mean_percentile = std::clamp<int>(optarg ? std::atoi(optarg) : 90, 1, 99);
            break;
        default:
            print_usage_exit(1);
            break;
        }
    }

    if (argc != optind + 1)
    {
        print_usage_exit(1);
    }

    args.trace_file = argv[optind];

    return args;
}

bool is_substring(
    const char* term,
    const char* s,
    bool case_sensitive = false
){
    auto new_term = std::string(term);
    auto new_s = std::string(s);

    if (!case_sensitive) {
        std::transform(
            new_term.begin(),
            new_term.end(),
            new_term.begin(),
            [](unsigned char c){ return std::tolower(c); }
        );

        std::transform(
            new_s.begin(),
            new_s.end(),
            new_s.begin(),
            [](unsigned char c){ return std::tolower(c); }
        );
    }

    return new_s.find(new_term) != std::string::npos;
}

const char* get_name(int32_t id, const tracy::Worker& worker)
{
    auto& srcloc = worker.GetSourceLocation(id);
    return worker.GetString(srcloc.name.active ? srcloc.name : srcloc.function);
}

template <typename T>
std::string join(const T& v, const char* sep) {
    std::ostringstream s;
    for (const auto& i : v) {
        if (&i != &v[0]) {
            s << sep;
        }
        s << i;
    }
    return s.str();
}

// Returns {pN, truncated_mean}
std::pair<int64_t, int64_t> percentile_and_truncated_mean(std::vector<int64_t>& data, const double p)
{
    assert(p >= 0.0 && p <= 1.0);

    if (data.empty()) {
        return {0, 0};
    }

    std::sort(data.begin(), data.end());

    const std::size_t n = data.size();
    const double idx = p * (static_cast<double>(n) - 1.0);
    const std::size_t idxLow = static_cast<std::size_t>(std::floor(idx));
    const std::size_t idxHigh = std::min(idxLow + 1, n - 1);
    const double frac = idx - static_cast<double>(idxLow);

    const double low = static_cast<double>(data[idxLow]);
    const double high = static_cast<double>(data[idxHigh]);

    // percentile value
    const double pval_double = low + (high - low) * frac;
    const int64_t pval_int = static_cast<int64_t>(std::llround(pval_double));

    // Compute truncated mean: average of all values <= pval_double
    int64_t sum = 0;
    std::size_t count = 0;
    for (std::size_t i = 0; i < n; ++i) {
        if (static_cast<double>(data[i]) <= pval_double) {
            sum += data[i];
            ++count;
        } else {
            break; // sorted, so we can stop once we hit > pval_double
        }
    }

    if (count == 0) {
        // should not happen for p in [0,1] unless data empty, but keep defensive behaviour
        return {pval_int, 0};
    }

    const int64_t truncated_mean = sum / count;

    return {pval_int, truncated_mean};
}


// From TracyView.cpp
int64_t GetZoneChildTimeFast(
    const tracy::Worker& worker,
    const tracy::ZoneEvent& zone
){
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

int main(int argc, char** argv)
{
#ifdef _WIN32
    if (!AttachConsole(ATTACH_PARENT_PROCESS))
    {
        AllocConsole();
        SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), 0x07);
    }
#endif

    Args args = parse_args(argc, argv);

    auto f = std::unique_ptr<tracy::FileRead>(
        tracy::FileRead::Open(args.trace_file)
    );
    if (!f)
    {
        fprintf(stderr, "Could not open file %s\n", args.trace_file);
        return 1;
    }

    auto worker = tracy::Worker(*f);

    if (args.unwrapMessages) 
    {
        const auto& msgs = worker.GetMessages();
    
        if (msgs.size() > 0)
        {
            std::vector<const char*> columnsForMessages;
            columnsForMessages = {
                    "MessageName", "total_ns"
                };
            std::string headerForMessages = join(columnsForMessages, args.separator);
            printf("%s\n", headerForMessages.data());

            for(auto& it : msgs)
            {
                std::vector<std::string> values(columnsForMessages.size());

                values[0] = worker.GetString(it->ref);
                values[1] = std::to_string(it->time);

                std::string row = join(values, args.separator);
                printf("%s\n", row.data());
            }
        }
        else
        {
            printf("There are currently no messages!\n");
        }
    
        return 0;
    }

    while (!worker.AreSourceLocationZonesReady())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (args.show_gpu)
    {
        auto& gpu_slz = worker.GetGpuSourceLocationZones();
        tracy::Vector<decltype( gpu_slz.begin() )> gpu_slz_selected;
        gpu_slz_selected.reserve( gpu_slz.size() );

        uint32_t total_cnt = 0;
        for (auto it = gpu_slz.begin(); it != gpu_slz.end(); ++it)
        {
            if (it->second.total != 0)
            {
                ++total_cnt;
                if (args.filter[0] == '\0')
                {
                    gpu_slz_selected.push_back_no_space_check( it );
                }
                else
                {
                    auto name = get_name( it->first, worker );
                    if (is_substring( args.filter, name, args.case_sensitive))
                    {
                        gpu_slz_selected.push_back_no_space_check( it );
                    }
                }
            }
        }

        std::vector<const char*> columns;
        columns = {"name", "src_file", "Time from start of program", "GPU execution time"};

        std::string header = join(columns, args.separator);
        printf("%s\n", header.data());

        const auto last_time = worker.GetLastTime();
        for (auto& it : gpu_slz_selected)
        {
            std::vector<std::string> values( columns.size() );

            values[0] = get_name( it->first, worker );

            const auto& srcloc = worker.GetSourceLocation( it->first );
            values[1] = worker.GetString( srcloc.file );

            const auto& zone_data = it->second;
            for (const auto& zone_thread_data : zone_data.zones)
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
    tracy::Vector<decltype(slz.begin())> slz_selected;
    slz_selected.reserve(slz.size());

    uint32_t total_cnt = 0;
    for(auto it = slz.begin(); it != slz.end(); ++it)
    {
        if(it->second.total != 0)
        {
            ++total_cnt;
            if(args.filter[0] == '\0')
            {
                slz_selected.push_back_no_space_check(it);
            }
            else
            {
                auto name = get_name(it->first, worker);
                if(is_substring(args.filter, name, args.case_sensitive))
                {
                    slz_selected.push_back_no_space_check(it);
                }
            }
        }
    }

    std::vector<const char*> columns;
    if (args.unwrap)
    {
        columns = {
            "name", "src_file", "src_line", "ns_since_start", "exec_time_ns", "thread", "value"
        };
    }
    else
    {
        columns = {
            "name", "src_file", "src_line", "total_ns", "total_perc",
            "counts", "mean_ns", "min_ns", "max_ns", "std_ns"
        };

        if(args.truncated_mean_percentile)
        {
            columns.push_back("percentile_ns");
            columns.push_back("truncated_mean_ns");
        }
    }
    std::string header = join(columns, args.separator);
    printf("%s\n", header.data());

    const auto last_time = worker.GetLastTime();
    for(auto& it : slz_selected)
    {
        std::vector<std::string> values(columns.size());

        values[0] = get_name(it->first, worker);

        const auto& srcloc = worker.GetSourceLocation(it->first);
        values[1] = worker.GetString(srcloc.file);
        values[2] = std::to_string(srcloc.line);

        const auto& zone_data = it->second;

        if (args.unwrap)
        {
            int i = 0;
            for (const auto& zone_thread_data : zone_data.zones) {
                const auto zone_event = zone_thread_data.Zone();
                const auto tId = zone_thread_data.Thread();
                const auto start = zone_event->Start();
                const auto end = zone_event->End();

                values[3] = std::to_string(start);

                auto timespan = end - start;
                if (args.self_time) {
                    timespan -= GetZoneChildTimeFast(worker, *zone_event);
                }
                values[4] = std::to_string(timespan);
                values[5] = std::to_string(tId);
                if (worker.HasZoneExtra(*zone_event)) {
                    const auto& text = worker.GetZoneExtra(*zone_event).text;
                    if (text.Active()) {
                        values[6] = worker.GetString(text);
                    }
                }

                std::string row = join(values, args.separator);
                printf("%s\n", row.data());
            }
        }
        else
        {
            const auto time = args.self_time ? zone_data.selfTotal : zone_data.total;
            values[3] = std::to_string(time);
            values[4] = std::to_string(100. * time / last_time);

            const auto sz = zone_data.zones.size();
            values[5] = std::to_string(sz);

            const auto avg = time / sz;

            values[6] = std::to_string(avg);

            const auto tmin = args.self_time ? zone_data.selfMin : zone_data.min;
            const auto tmax = args.self_time ? zone_data.selfMax : zone_data.max;
            values[7] = std::to_string(tmin);
            values[8] = std::to_string(tmax);

            const auto ss = zone_data.sumSq
                - 2. * zone_data.total * avg
                + avg * avg * sz;
            double std = 0;
            if( sz > 1 )
                std = sqrt(ss / (sz - 1));
            values[9] = std::to_string(std);

            if(args.truncated_mean_percentile)
            {
                std::vector<int64_t> samples;
                samples.reserve( zone_data.zones.size() );
                for(const auto& zone_thread_data : zone_data.zones)
                {
                    const auto zone_event = zone_thread_data.Zone();
                    auto timespan = zone_event->End() - zone_event->Start();
                    if(args.self_time)
                        timespan -= GetZoneChildTimeFast( worker, *zone_event );
                    samples.push_back( timespan );
                }

                std::pair<int64_t, int64_t> pN = percentile_and_truncated_mean(samples, args.truncated_mean_percentile / 100.0);
                values[10] = std::to_string(pN.first);
                values[11] = std::to_string(pN.second);
            }

            std::string row = join(values, args.separator);
            printf("%s\n", row.data());
        }
    }

    if(args.plot && args.unwrap)
    {
        auto& plots = worker.GetPlots();
        for(const auto& plot : plots)
        {
            std::vector<std::string> values(columns.size());
            values[0] = worker.GetString(plot->name);

            for(const auto& val : plot->data)
            {
                if (args.unwrap)
                {
                    values[3] = std::to_string(val.time.Val());
                    values[6] = std::to_string(val.val);
                }
                std::string row = join(values, args.separator);
                printf("%s\n", row.data());
            }
        }
    }

    return 0;
}
