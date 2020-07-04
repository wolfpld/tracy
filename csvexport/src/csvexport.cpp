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
#include "cxxopts.hpp"

struct Args {
    std::string filter;
    std::string separator;
    std::string trace_file;
    bool case_sensitive;
    bool self_time;
    bool unwrap;
};

Args parse_args(int argc, char** argv)
{
    cxxopts::Options options(
        "extract",
        "Extract statistics from a trace to a CSV format"
    );

    std::string filter;
    std::string separator;
    std::string trace_file;
    bool case_sensitive = false;
    bool self_time = false;
    bool unwrap = false;

	options.add_options()
        ("h,help", "Print usage")
        ("f,filter", "Filter zone names",
            cxxopts::value(filter)->default_value(""))
        ("s,separator", "CSV separator",
            cxxopts::value(separator)->default_value(","))
        ("t,trace", "same as <trace file>",
            cxxopts::value(trace_file))
        ("case", "Case sensitive filtering",
            cxxopts::value(case_sensitive))
        ("self", "Get self times",
            cxxopts::value(self_time))
        ("unwrap", "Report each zone event",
            cxxopts::value(unwrap))
    ;

    options.positional_help("<trace file>");
    options.parse_positional("trace");
    auto result = options.parse(argc, argv);
    if (result.count("help"))
    {
        fprintf(stderr, "%s\n", options.help().data());
        exit(0);
    }

    if (result.count("trace") == 0)
    {
        fprintf(stderr, "Requires a trace file");
        exit(1);
    }

    return Args {
        filter, separator, trace_file, case_sensitive, self_time, unwrap
    };
}

bool is_substring(
    const std::string term,
    const std::string s,
    bool case_sensitive = false
){
    std::string new_term = term;
    std::string new_s = s;

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
std::string join(const T& v, std::string sep) {
    std::ostringstream s;
    for (const auto& i : v) {
        if (&i != &v[0]) {
            s << sep;
        }
        s << i;
    }
    return s.str();
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
    Args args = parse_args(argc, argv);

    auto f = std::unique_ptr<tracy::FileRead>(
        tracy::FileRead::Open(args.trace_file.data())
    );
    if (!f)
    {
        fprintf(stderr, "Could not open file %s\n", args.trace_file.data());
        return 1;
    }

    auto worker = tracy::Worker(*f);

    while (!worker.AreSourceLocationZonesReady())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
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
            if(args.filter.empty())
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
            "name", "src_file", "src_line", "ns_since_start", "exec_time_ns"
        };
    }
    else
    {
        columns = {
            "name", "src_file", "src_line", "total_ns", "total_perc",
            "counts", "mean_ns", "min_ns", "max_ns", "std_ns"
        };
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
                const auto start = zone_event->Start();
                const auto end = zone_event->End();

                values[3] = std::to_string(start);

                auto timespan = end - start;
                if (args.self_time) {
                    timespan -= GetZoneChildTimeFast(worker, *zone_event);
                }
                values[4] = std::to_string(timespan);

                std::string row = join(values, args.separator);
                printf("%s\n", row.data());
            }
        }
        else
        {
            const auto time = args.self_time ? zone_data.selfTotal : zone_data.total;
            values[3] = std::to_string(time);
            values[4] = std::to_string(100. * time / last_time);

            values[5] = std::to_string(zone_data.zones.size());

            const auto avg = (args.self_time ? zone_data.selfTotal : zone_data.total)
                / zone_data.zones.size();
            values[6] = std::to_string(avg);

            const auto tmin = args.self_time ? zone_data.selfMin : zone_data.min;
            const auto tmax = args.self_time ? zone_data.selfMax : zone_data.max;
            values[7] = std::to_string(tmin);
            values[8] = std::to_string(tmax);

            const auto sz = zone_data.zones.size();
            const auto ss = zone_data.sumSq
                - 2. * zone_data.total * avg
                + avg * avg * sz;
            const auto std = sqrt(ss / (sz - 1));
            values[9] = std::to_string(std);

            std::string row = join(values, args.separator);
            printf("%s\n", row.data());
        }
    }

    return 0;
}
