#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <unordered_map>

#ifdef _MSC_VER
#  pragma warning( push )
#  pragma warning( disable : 4244 4267 )  // third-party ppqsort: narrowing conversions
#elif defined( __GNUC__ )
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wnarrowing"
#endif
#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyWorker.hpp"
#ifdef _MSC_VER
#  pragma warning( pop )
#elif defined( __GNUC__ )
#  pragma GCC diagnostic pop
#endif

namespace py = pybind11;
using namespace pybind11::literals;

namespace tracy
{

PYBIND11_MODULE( TracyServerBindings, m )
{
    m.doc() = "Tracy Server (Analysis) Bindings";

    // -------------------------------------------------------------------------
    // SourceLocation
    // -------------------------------------------------------------------------
    py::class_<SourceLocation>( m, "SourceLocation" )
        .def_readonly( "line", &SourceLocation::line );

    // -------------------------------------------------------------------------
    // ZoneStats — POD summary returned by zone stat helpers
    // -------------------------------------------------------------------------
    struct ZoneStats
    {
        int64_t min;
        int64_t max;
        int64_t total;
        double sumSq;
        size_t count;
        double avg;
    };

    py::class_<ZoneStats>( m, "ZoneStats" )
        .def_readonly( "min", &ZoneStats::min )
        .def_readonly( "max", &ZoneStats::max )
        .def_readonly( "total", &ZoneStats::total )
        .def_readonly( "sum_sq", &ZoneStats::sumSq )
        .def_readonly( "count", &ZoneStats::count )
        .def_readonly( "avg", &ZoneStats::avg );

    // GpuZoneStats — GPU timestamps are the same int64_t nanosecond type;
    // reuse ZoneStats rather than duplicating the struct.
    using GpuZoneStats = ZoneStats;

    // -------------------------------------------------------------------------
    // FrameStats — per-frame-set timing summary
    // -------------------------------------------------------------------------
    struct FrameStats
    {
        std::string name;
        int64_t min;
        int64_t max;
        int64_t total;
        double sumSq;
        size_t count;
        double avg;
    };

    py::class_<FrameStats>( m, "FrameStats" )
        .def_readonly( "name", &FrameStats::name )
        .def_readonly( "min", &FrameStats::min )
        .def_readonly( "max", &FrameStats::max )
        .def_readonly( "total", &FrameStats::total )
        .def_readonly( "sum_sq", &FrameStats::sumSq )
        .def_readonly( "count", &FrameStats::count )
        .def_readonly( "avg", &FrameStats::avg );

    // -------------------------------------------------------------------------
    // PlotSummary
    // -------------------------------------------------------------------------
    struct PlotSummary
    {
        std::string name;
        double min;
        double max;
        double sum;
        size_t count;
        double avg;
        std::string type;
    };

    py::class_<PlotSummary>( m, "PlotSummary" )
        .def_readonly( "name", &PlotSummary::name )
        .def_readonly( "min", &PlotSummary::min )
        .def_readonly( "max", &PlotSummary::max )
        .def_readonly( "sum", &PlotSummary::sum )
        .def_readonly( "count", &PlotSummary::count )
        .def_readonly( "avg", &PlotSummary::avg )
        .def_readonly( "type", &PlotSummary::type );

    // -------------------------------------------------------------------------
    // MemPoolSummary
    // -------------------------------------------------------------------------
    struct MemPoolSummary
    {
        std::string name;
        uint64_t high;
        uint64_t low;
        uint64_t usage;
        size_t alloc_count;
    };

    py::class_<MemPoolSummary>( m, "MemPoolSummary" )
        .def_readonly( "name", &MemPoolSummary::name )
        .def_readonly( "high", &MemPoolSummary::high )
        .def_readonly( "low", &MemPoolSummary::low )
        .def_readonly( "usage", &MemPoolSummary::usage )
        .def_readonly( "alloc_count", &MemPoolSummary::alloc_count );

    // -------------------------------------------------------------------------
    // LockSummary
    // -------------------------------------------------------------------------
    struct LockSummary
    {
        std::string name;
        bool is_contended;
        std::string type;
        int64_t time_announce;
        int64_t time_terminate;
        std::vector<uint64_t> threads;
    };

    py::class_<LockSummary>( m, "LockSummary" )
        .def_readonly( "name", &LockSummary::name )
        .def_readonly( "is_contended", &LockSummary::is_contended )
        .def_readonly( "type", &LockSummary::type )
        .def_readonly( "time_announce", &LockSummary::time_announce )
        .def_readonly( "time_terminate", &LockSummary::time_terminate )
        .def_readonly( "threads", &LockSummary::threads );

    // -------------------------------------------------------------------------
    // GpuContextSummary
    // -------------------------------------------------------------------------
    struct GpuContextSummary
    {
        std::string name;
        uint64_t count;
        std::string type;
        uint64_t thread;
    };

    py::class_<GpuContextSummary>( m, "GpuContextSummary" )
        .def_readonly( "name", &GpuContextSummary::name )
        .def_readonly( "count", &GpuContextSummary::count )
        .def_readonly( "type", &GpuContextSummary::type )
        .def_readonly( "thread", &GpuContextSummary::thread );

    // -------------------------------------------------------------------------
    // MessageInfo
    // -------------------------------------------------------------------------
    struct MessageInfo
    {
        int64_t time;
        std::string text;
        uint32_t color;
        uint64_t thread;
    };

    py::class_<MessageInfo>( m, "MessageInfo" )
        .def_readonly( "time", &MessageInfo::time )
        .def_readonly( "text", &MessageInfo::text )
        .def_readonly( "color", &MessageInfo::color )
        .def_readonly( "thread", &MessageInfo::thread );

    // ThreadData — get_threads() returns plain dicts to avoid pybind11
    // raw-pointer ownership issues, so no class registration is needed.

    // -------------------------------------------------------------------------
    // Worker
    // -------------------------------------------------------------------------
    auto worker_cls = py::class_<Worker>( m, "Worker" );
    worker_cls
        // Construction
        .def( py::init<const char*, uint16_t, int64_t>(), "addr"_a, "port"_a, "memoryLimit"_a = -1 )

        // --- Capture metadata ---
        .def( "get_capture_name", &Worker::GetCaptureName )
        .def( "get_capture_program", &Worker::GetCaptureProgram )
        .def( "get_capture_time", &Worker::GetCaptureTime )
        .def( "get_host_info", &Worker::GetHostInfo )
        .def( "get_pid", &Worker::GetPid )
        .def( "get_resolution", &Worker::GetResolution )
        .def( "get_first_time", &Worker::GetFirstTime )
        .def( "get_last_time", &Worker::GetLastTime )
        .def( "get_cpu_manufacturer", &Worker::GetCpuManufacturer )

        // --- Counts ---
        .def( "get_zone_count", &Worker::GetZoneCount )
        .def( "get_gpu_zone_count", &Worker::GetGpuZoneCount )
        .def( "get_lock_count", &Worker::GetLockCount )
        .def( "get_plot_count", &Worker::GetPlotCount )
        .def( "get_context_switch_count", &Worker::GetContextSwitchCount )
        .def( "get_src_loc_count", &Worker::GetSrcLocCount )
        .def( "get_callstack_sample_count", &Worker::GetCallstackSampleCount )
        .def( "get_message_count", []( const Worker& w ) {
        return w.GetMessages().size();
    } )

        // --- Source locations / zones ---
        .def( "get_src_loc", []( const Worker& w, int16_t id ) {
        return w.GetSourceLocation( id );
    } ).def( "get_zone_name", []( const Worker& w, int16_t id ) {
        return w.GetZoneName( w.GetSourceLocation( id ) );
    } )
#ifndef TRACY_NO_STATISTICS
        .def( "get_zone_stats", []( const Worker& w, int16_t id ) {
        const auto& stats = w.GetZonesForSourceLocation( id );
        const size_t cnt = stats.zones.size();
        return ZoneStats{ stats.min, stats.max, stats.total, stats.sumSq, cnt, cnt ? (double)stats.total / cnt : 0.0 };
    } )
#endif
        .def( "get_all_zone_stats", []( const Worker& w ) {
        py::dict result;
#ifndef TRACY_NO_STATISTICS
        for( const auto& kv : w.GetSourceLocationZones() )
        {
            const auto& stats = kv.second;
            if( stats.zones.size() == 0 ) continue;
            const auto& sl = w.GetSourceLocation( kv.first );
            const char* name = w.GetZoneName( sl );
            const size_t cnt = stats.zones.size();
            result[name] = ZoneStats{ stats.min, stats.max, stats.total, stats.sumSq, cnt, (double)stats.total / cnt };
        }
#endif
        return result;
    } ).def( "get_root_zone_stats", []( const Worker& w ) {
            // Aggregate stats for top-level (root) zones only — no nesting, safe to sum
            // File-loaded data uses is_magic() — zones stored inline, not as short_ptr
        struct Acc
        {
            int64_t min = INT64_MAX, max = INT64_MIN, total = 0;
            double sumSq = 0;
            size_t count = 0;
        };
        std::unordered_map<int16_t, Acc> acc;
        auto processRoot = [&]( const ZoneEvent& z ) {
            if( !z.IsEndValid() ) return;
            const int64_t dur = z.End() - z.Start();
            auto& s = acc[z.SrcLoc()];
            s.total += dur;
            s.count++;
            if( dur < s.min ) s.min = dur;
            if( dur > s.max ) s.max = dur;
        };
        for( const auto* td : w.GetThreadData() )
        {
            if( !td ) continue;
            if( td->timeline.is_magic() )
            {
                for( const auto& z : *(const Vector<ZoneEvent>*)&td->timeline ) processRoot( z );
            }
            else
            {
                for( const auto& zptr : td->timeline )
                {
                    if( const ZoneEvent* z = zptr.get() ) processRoot( *z );
                }
            }
        }
        py::dict result;
        for( const auto& kv : acc )
        {
            const auto& s = kv.second;
            const double avg = (double)s.total / s.count;
            const char* name = w.GetZoneName( w.GetSourceLocation( kv.first ) );
            result[name] = ZoneStats{ s.min, s.max, s.total, s.sumSq, s.count, avg };
        }
        return result;
    } )

        // --- Per-occurrence zone data (for temporal correlation / distribution) ---
        .def( "get_zone_durations", []( const Worker& w, const std::string& name, size_t maxSamples ) {
            // Accumulates across ALL srclocs with this name (same name can appear at multiple srclocs)
        std::vector<int64_t> result;
#ifndef TRACY_NO_STATISTICS
        for( const auto& kv : w.GetSourceLocationZones() )
        {
            if( std::string( w.GetZoneName( w.GetSourceLocation( kv.first ) ) ) != name ) continue;
            for( const auto& ztd : kv.second.zones )
            {
                if( result.size() >= maxSamples ) goto done_durations;
                const auto* z = ztd.Zone();
                if( z && z->IsEndValid() ) result.push_back( z->End() - z->Start() );
            }
        }
    done_durations:;
#endif
        return result;
    }, "name"_a, "max_samples"_a = 100000 )
        .def( "get_zone_occurrences", []( const Worker& w, const std::string& name, size_t maxSamples ) {
            // Returns list of (start_ns, duration_ns) — accumulates across all srclocs with this name
        std::vector<std::pair<int64_t, int64_t>> result;
#ifndef TRACY_NO_STATISTICS
        for( const auto& kv : w.GetSourceLocationZones() )
        {
            if( std::string( w.GetZoneName( w.GetSourceLocation( kv.first ) ) ) != name ) continue;
            for( const auto& ztd : kv.second.zones )
            {
                if( result.size() >= maxSamples ) goto done_occurrences;
                const auto* z = ztd.Zone();
                if( z && z->IsEndValid() ) result.emplace_back( z->Start(), z->End() - z->Start() );
            }
        }
    done_occurrences:;
#endif
        return result;
    }, "name"_a, "max_samples"_a = 100000 )
        .def( "get_zone_annotations", []( const Worker& w, const std::string& name, size_t maxSamples ) {
            // Returns text annotations attached to individual zone occurrences
        std::vector<std::string> result;
#ifndef TRACY_NO_STATISTICS
        for( const auto& kv : w.GetSourceLocationZones() )
        {
            if( std::string( w.GetZoneName( w.GetSourceLocation( kv.first ) ) ) != name ) continue;
            for( const auto& ztd : kv.second.zones )
            {
                if( result.size() >= maxSamples ) goto done_annotations;
                const auto* z = ztd.Zone();
                if( z && w.HasZoneExtra( *z ) )
                {
                    const auto& extra = w.GetZoneExtra( *z );
                    if( extra.text.Active() ) result.push_back( w.GetString( extra.text ) );
                }
            }
        }
    done_annotations:;
#endif
        return result;
    }, "name"_a, "max_samples"_a = 10000 )
        .def( "get_gpu_zone_durations", []( const Worker& w, const std::string& name, size_t maxSamples ) {
        std::vector<int64_t> result;
        for( const auto& kv : w.GetGpuSourceLocationZones() )
        {
            if( std::string( w.GetZoneName( w.GetSourceLocation( kv.first ) ) ) != name ) continue;
            for( const auto& ztd : kv.second.zones )
            {
                if( result.size() >= maxSamples ) goto done_gpu_dur;
                const auto* z = ztd.Zone();
                if( z && z->GpuEnd() >= 0 ) result.push_back( z->GpuEnd() - z->GpuStart() );
            }
        }
    done_gpu_dur:;
        return result;
    }, "name"_a, "max_samples"_a = 100000 )
        .def( "get_gpu_zone_occurrences", []( const Worker& w, const std::string& name, size_t maxSamples ) {
        std::vector<std::pair<int64_t, int64_t>> result;
        for( const auto& kv : w.GetGpuSourceLocationZones() )
        {
            if( std::string( w.GetZoneName( w.GetSourceLocation( kv.first ) ) ) != name ) continue;
            for( const auto& ztd : kv.second.zones )
            {
                if( result.size() >= maxSamples ) goto done_gpu_occ;
                const auto* z = ztd.Zone();
                if( z && z->GpuEnd() >= 0 ) result.emplace_back( z->GpuStart(), z->GpuEnd() - z->GpuStart() );
            }
        }
    done_gpu_occ:;
        return result;
    }, "name"_a, "max_samples"_a = 100000 )

        // --- Callstack resolution ---
        .def( "get_callstack_frames", []( const Worker& w, uint32_t callstackIdx ) {
        py::list result;
        const auto& cs = w.GetCallstack( callstackIdx );
        for( size_t i = 0; i < cs.size(); ++i )
        {
            const auto* fd = w.GetCallstackFrame( cs[i] );
            if( !fd ) continue;
            for( uint8_t j = 0; j < fd->size; ++j )
            {
                const auto& frame = fd->data[j];
                py::dict d;
                d["name"] = std::string( w.GetString( frame.name ) );
                d["file"] = std::string( w.GetString( frame.file ) );
                d["line"] = frame.line;
                d["addr"] = frame.symAddr;
                result.append( d );
            }
        }
        return result;
    }, "callstack_idx"_a )

        // --- Context switches per thread ---
        .def( "get_thread_context_switches", []( const Worker& w, uint64_t tid, size_t maxSamples ) {
        py::list result;
        const auto* cs = const_cast<Worker&>( w ).GetContextSwitchData( tid );
        if( !cs ) return result;
        for( const auto& ev : cs->v )
        {
            if( (size_t)result.size() >= maxSamples ) break;
            if( !ev.IsEndValid() ) continue;
            py::dict d;
            d["start"] = ev.Start();
            d["end"] = ev.End();
            d["cpu"] = (int)ev.Cpu();
            d["reason"] = (int)ev.Reason();
            result.append( d );
        }
        return result;
    }, "tid"_a, "max_samples"_a = 50000 )

        // --- CPU thread running time / migrations ---
        .def( "get_cpu_thread_data", []( const Worker& w ) {
        py::dict result;
        for( const auto& kv : w.GetCpuThreadData() )
        {
            py::dict d;
            d["running_time"] = kv.second.runningTime;
            d["running_regions"] = kv.second.runningRegions;
            d["migrations"] = kv.second.migrations;
            result[py::int_( kv.first )] = d;
        }
        return result;
    } )

        // --- Zone occurrences with thread attribution ---
        .def( "get_zone_occurrences_with_thread", []( const Worker& w, const std::string& name, size_t maxSamples ) {
            // Returns list of (start_ns, duration_ns, thread_id) — thread_id is the OS thread ID
        std::vector<std::tuple<int64_t, int64_t, uint64_t>> result;
#ifndef TRACY_NO_STATISTICS
        const auto& threads = w.GetThreadData();
        for( const auto& kv : w.GetSourceLocationZones() )
        {
            if( std::string( w.GetZoneName( w.GetSourceLocation( kv.first ) ) ) != name ) continue;
            for( const auto& ztd : kv.second.zones )
            {
                if( result.size() >= maxSamples ) goto done_occ_thread;
                const auto* z = ztd.Zone();
                if( !z || !z->IsEndValid() ) continue;
                const uint16_t tidx = ztd.Thread();
                const uint64_t tid = ( tidx < threads.size() && threads[tidx] ) ? threads[tidx]->id : 0;
                result.emplace_back( z->Start(), z->End() - z->Start(), tid );
            }
        }
    done_occ_thread:;
#endif
        return result;
    }, "name"_a, "max_samples"_a = 100000 )

        // --- Child zone stats: aggregate direct children of all occurrences of a parent zone ---
        .def( "get_child_zone_stats", []( const Worker& w, const std::string& name, size_t maxParents ) {
            // Uses SourceLocationZones for O(occurrences) lookup — avoids walking the full zone tree.
            // File-loaded data sets is_magic() on child vectors (inline ZoneEvent, not short_ptr).
        struct Acc
        {
            int64_t min = INT64_MAX, max = INT64_MIN, total = 0;
            double sumSq = 0.0;
            size_t count = 0;
        };
        std::unordered_map<int16_t, Acc> acc;
        size_t parentCount = 0;

        auto accumChild = [&]( const ZoneEvent& c ) {
            if( !c.IsEndValid() ) return;
            const int64_t dur = c.End() - c.Start();
            auto& s = acc[c.SrcLoc()];
            s.total += dur;
            s.count++;
            s.sumSq += (double)dur * dur;
            if( dur < s.min ) s.min = dur;
            if( dur > s.max ) s.max = dur;
        };

#ifndef TRACY_NO_STATISTICS
        for( const auto& kv : w.GetSourceLocationZones() )
        {
            if( std::string( w.GetZoneName( w.GetSourceLocation( kv.first ) ) ) != name ) continue;
            for( const auto& ztd : kv.second.zones )
            {
                if( parentCount >= maxParents ) goto done_children;
                const auto* z = ztd.Zone();
                if( !z || !z->IsEndValid() || !z->HasChildren() ) continue;
                parentCount++;
                const auto& ch = w.GetZoneChildren( z->Child() );
                if( ch.is_magic() )
                {
                    for( const auto& c : *(const Vector<ZoneEvent>*)&ch ) accumChild( c );
                }
                else
                {
                    for( const auto& cptr : ch )
                    {
                        if( const ZoneEvent* c = cptr.get() ) accumChild( *c );
                    }
                }
            }
        }
    done_children:;
#endif
        py::dict result;
        for( const auto& kv : acc )
        {
            const auto& s = kv.second;
            if( s.count == 0 ) continue;
            const double avg = (double)s.total / (double)s.count;
            const char* cname = w.GetZoneName( w.GetSourceLocation( kv.first ) );
            result[cname] = ZoneStats{ s.min, s.max, s.total, s.sumSq, s.count, avg };
        }
        return result;
    }, "name"_a, "max_parents"_a = 100000 )

        // --- Zone source location (file / line / function for LLM code navigation) ---
        .def( "get_zone_source_location", []( const Worker& w, const std::string& name ) {
        py::dict result;
#ifndef TRACY_NO_STATISTICS
        for( const auto& kv : w.GetSourceLocationZones() )
        {
            const auto& sl = w.GetSourceLocation( kv.first );
            if( std::string( w.GetZoneName( sl ) ) != name ) continue;
            result["name"] = name;
            result["function"] = std::string( w.GetString( sl.function ) );
            result["file"] = std::string( w.GetString( sl.file ) );
            result["line"] = sl.line;
            result["color"] = sl.color;
            break;
        }
#endif
        return result;
    }, "name"_a )
        .def( "get_all_zone_source_locations", []( const Worker& w ) {
            // Returns {zone_name: {file, line, function, color}} for every unique zone name.
            // Uses first srcloc found per name — sufficient for navigation purposes.
        py::dict result;
#ifndef TRACY_NO_STATISTICS
        for( const auto& kv : w.GetSourceLocationZones() )
        {
            const auto& sl = w.GetSourceLocation( kv.first );
            const char* name = w.GetZoneName( sl );
            if( result.contains( name ) ) continue;
            py::dict d;
            d["function"] = std::string( w.GetString( sl.function ) );
            d["file"] = std::string( w.GetString( sl.file ) );
            d["line"] = sl.line;
            d["color"] = sl.color;
            result[name] = d;
        }
#endif
        return result;
    } )

        // --- Per-zone callstack samples (call paths leading into a zone) ---
        .def( "get_zone_callstacks", []( const Worker& w, const std::string& name, size_t maxSamples ) {
        py::list result;
#ifndef TRACY_NO_STATISTICS
        for( const auto& kv : w.GetSourceLocationZones() )
        {
            if( std::string( w.GetZoneName( w.GetSourceLocation( kv.first ) ) ) != name ) continue;
            for( const auto& ztd : kv.second.zones )
            {
                if( (size_t)result.size() >= maxSamples ) goto done_callstacks;
                const auto* z = ztd.Zone();
                if( !z || !w.HasZoneExtra( *z ) ) continue;
                const auto& extra = w.GetZoneExtra( *z );
                const uint32_t csIdx = extra.callstack.Val();
                if( csIdx == 0 ) continue;
                py::list frames;
                const auto& cs = w.GetCallstack( csIdx );
                for( size_t i = 0; i < cs.size(); ++i )
                {
                    const auto* fd = w.GetCallstackFrame( cs[i] );
                    if( !fd ) continue;
                    for( uint8_t j = 0; j < fd->size; ++j )
                    {
                        const auto& frame = fd->data[j];
                        py::dict d;
                        d["name"] = std::string( w.GetString( frame.name ) );
                        d["file"] = std::string( w.GetString( frame.file ) );
                        d["line"] = frame.line;
                        d["addr"] = frame.symAddr;
                        frames.append( d );
                    }
                }
                result.append( frames );
            }
        }
    done_callstacks:;
#endif
        return result;
    }, "name"_a, "max_samples"_a = 1000 )

        // --- Symbol-level sampling stats (inclusive / exclusive counts from call-stack profiling) ---
        .def( "get_symbol_stats", []( const Worker& w ) {
        py::list result;
        for( const auto& kv : w.GetSymbolStats() )
        {
            const uint64_t addr = kv.first;
            const auto& stats = kv.second;
            py::dict d;
            d["addr"] = addr;
            d["incl"] = stats.incl;
            d["excl"] = stats.excl;
            const auto* sym = w.GetSymbolData( addr );
            if( sym )
            {
                d["name"] = std::string( w.GetString( sym->name ) );
                d["file"] = std::string( w.GetString( sym->file ) );
                d["line"] = sym->line;
                d["image"] = std::string( w.GetString( sym->imageName ) );
            }
            result.append( d );
        }
        return result;
    } )

        // --- Timestamps of all call-stack samples hitting a specific symbol ---
        .def( "get_samples_for_symbol", []( const Worker& w, uint64_t symAddr ) {
        py::list result;
        const auto* samples = w.GetSamplesForSymbol( symAddr );
        if( !samples ) return result;
        for( const auto& s : *samples )
        {
            py::dict d;
            d["time"] = s.time.Val();
            d["thread"] = (uint32_t)s.thread;
            result.append( d );
        }
        return result;
    }, "sym_addr"_a )

        // --- Hardware performance counter summary per symbol (IPC, cache-miss rate, branch-miss rate) ---
        .def( "get_hw_sample_summary", []( const Worker& w ) {
        py::list result;
        for( const auto& kv : w.GetSymbolStats() )
        {
            const uint64_t addr = kv.first;
            auto* hw = const_cast<Worker&>( w ).GetHwSampleData( addr );
            if( !hw || ( hw->cycles.empty() && hw->retired.empty() ) ) continue;
            auto mean = []( const auto& v ) -> double {
                if( v.empty() ) return 0.0;
                double sum = 0.0;
                for( const auto& x : v ) sum += (double)x.Val();
                return sum / (double)v.size();
            };
            const double cyc = mean( hw->cycles );
            const double ret = mean( hw->retired );
            const double cmr = mean( hw->cacheRef );
            const double cmm = mean( hw->cacheMiss );
            const double brr = mean( hw->branchRetired );
            const double brm = mean( hw->branchMiss );
            py::dict d;
            d["addr"] = addr;
            d["samples"] = hw->cycles.empty() ? hw->retired.size() : hw->cycles.size();
            d["cycles_mean"] = cyc;
            d["retired_mean"] = ret;
            d["cache_ref_mean"] = cmr;
            d["cache_miss_mean"] = cmm;
            d["branch_ret_mean"] = brr;
            d["branch_miss_mean"] = brm;
            d["ipc"] = ( cyc > 0.0 && ret > 0.0 ) ? ret / cyc : -1.0;
            d["cache_miss_rate"] = ( cmr > 0.0 ) ? cmm / cmr : -1.0;
            d["branch_miss_rate"] = ( brr > 0.0 ) ? brm / brr : -1.0;
            const auto* sym = w.GetSymbolData( addr );
            d["name"] = sym ? std::string( w.GetString( sym->name ) ) : std::string( "" );
            d["file"] = sym ? std::string( w.GetString( sym->file ) ) : std::string( "" );
            d["line"] = sym ? sym->line : 0u;
            d["image"] = sym ? std::string( w.GetString( sym->imageName ) ) : std::string( "" );
            result.append( d );
        }
        return result;
    } )

        // --- Raw memory allocation events (ptr, size, timestamps) for temporal zone correlation ---
        .def( "get_memory_events", []( const Worker& w, size_t maxCount, const std::string& poolName ) {
        py::list result;
        for( const auto& kv : w.GetMemNameMap() )
        {
            const std::string name = kv.first == 0
                                         ? std::string( "(default)" )
                                         : std::string( w.GetString( kv.first ) );
            if( !poolName.empty() && name != poolName ) continue;
            const MemData* md = kv.second;
            for( const auto& ev : md->data )
            {
                if( (size_t)result.size() >= maxCount ) break;
                py::dict d;
                d["pool"] = name;
                d["ptr"] = ev.Ptr();
                d["size"] = ev.Size();
                d["time_alloc"] = ev.TimeAlloc();
                d["time_free"] = ev.TimeFree();
                d["thread_alloc"] = (uint32_t)ev.ThreadAlloc();
                d["callstack_idx"] = (uint32_t)ev.CsAlloc();
                result.append( d );
            }
            if( !poolName.empty() ) break;
        }
        return result;
    }, "max_count"_a = 100000, "pool_name"_a = "" )

        // --- Per-lock wait/contention stats (total and average wait time) ---
        .def( "get_lock_wait_stats", []( const Worker& w ) {
        py::list result;
        for( const auto& kv : w.GetLockMap() )
        {
            const LockMap* lm = kv.second;
            if( !lm || !lm->valid || !lm->isContended ) continue;
            std::string name;
            if( lm->customName.Active() )
                name = w.GetString( lm->customName );
            else
                name = w.GetZoneName( w.GetSourceLocation( lm->srcloc ) );
            int64_t totalWaitNs = 0;
            uint64_t contentionCount = 0;
            std::unordered_map<uint8_t, int64_t> pendingWait;
            for( const auto& evPtr : lm->timeline )
            {
                const auto* ev = evPtr.ptr.get();
                if( !ev ) continue;
                if( ev->type == LockEvent::Type::Wait || ev->type == LockEvent::Type::WaitShared )
                {
                    pendingWait[ev->thread] = ev->Time();
                }
                else if( ev->type == LockEvent::Type::Obtain || ev->type == LockEvent::Type::ObtainShared )
                {
                    auto it = pendingWait.find( ev->thread );
                    if( it != pendingWait.end() )
                    {
                        totalWaitNs += ev->Time() - it->second;
                        contentionCount++;
                        pendingWait.erase( it );
                    }
                }
            }
            if( contentionCount == 0 ) continue;
            py::dict d;
            d["name"] = name;
            d["total_wait_ns"] = totalWaitNs;
            d["avg_wait_ns"] = (double)totalWaitNs / (double)contentionCount;
            d["contention_count"] = contentionCount;
            d["threads"] = lm->threadList;
            result.append( d );
        }
        return result;
    } )

        // --- GPU zone stats ---
        .def( "get_all_gpu_zone_stats", []( const Worker& w ) {
        py::dict result;
        for( const auto& kv : w.GetGpuSourceLocationZones() )
        {
            const auto& sl = w.GetSourceLocation( kv.first );
            const char* name = w.GetZoneName( sl );
            const auto& s = kv.second;
            const size_t cnt = s.zones.size();
            if( cnt > 0 )
                result[name] = GpuZoneStats{ s.min, s.max, s.total, s.sumSq, cnt, (double)s.total / cnt };
        }
        return result;
    } ).def( "get_gpu_child_zone_stats", []( const Worker& w, const std::string& name, size_t maxParents ) {
            // GPU equivalent of get_child_zone_stats — returns per-child-name GPU duration stats
            // for all occurrences of the named parent GPU zone.
        struct Acc
        {
            int64_t min = INT64_MAX, max = INT64_MIN, total = 0;
            double sumSq = 0.0;
            size_t count = 0;
        };
        std::unordered_map<int16_t, Acc> acc;
        size_t parentCount = 0;

        auto accumChild = [&]( const GpuEvent& c ) {
            if( c.GpuEnd() < 0 ) return;
            const int64_t dur = c.GpuEnd() - c.GpuStart();
            if( dur < 0 ) return;
            auto& s = acc[c.SrcLoc()];
            s.total += dur;
            s.count++;
            s.sumSq += (double)dur * dur;
            if( dur < s.min ) s.min = dur;
            if( dur > s.max ) s.max = dur;
        };

        for( const auto& kv : w.GetGpuSourceLocationZones() )
        {
            if( std::string( w.GetZoneName( w.GetSourceLocation( kv.first ) ) ) != name ) continue;
            for( const auto& ztd : kv.second.zones )
            {
                if( parentCount >= maxParents ) goto done_gpu_child;
                const auto* z = ztd.Zone();
                if( !z || z->GpuEnd() < 0 || z->Child() < 0 ) continue;
                parentCount++;
                for( const auto& cptr : w.GetGpuChildren( z->Child() ) )
                {
                    if( const GpuEvent* c = cptr.get() ) accumChild( *c );
                }
            }
        }
    done_gpu_child:;

        py::dict result;
        for( const auto& kv : acc )
        {
            const auto& s = kv.second;
            if( s.count == 0 ) continue;
            const char* cname = w.GetZoneName( w.GetSourceLocation( kv.first ) );
            result[cname] = GpuZoneStats{ s.min, s.max, s.total, s.sumSq, s.count, (double)s.total / s.count };
        }
        return result;
    }, "name"_a, "max_parents"_a = 100000 )

        // --- Frame sets ---
        .def( "get_frame_count", []( const Worker& w ) {
        auto frames = w.GetFramesBase();
        return frames ? w.GetFrameCount( *frames ) : 0;
    } ).def( "get_all_frame_stats", []( const Worker& w ) {
        std::vector<FrameStats> result;
        for( const auto* fd : w.GetFrames() )
        {
            if( !fd ) continue;
            const size_t cnt = fd->frames.size();
            const std::string name = w.GetString( fd->name );
            result.push_back( FrameStats{
                name, fd->min, fd->max, fd->total, fd->sumSq,
                cnt, cnt ? (double)fd->total / cnt : 0.0 } );
        }
        return result;
    } ).def( "get_frame_boundaries", []( const Worker& w ) {
        auto* fd = w.GetFramesBase();
        if( !fd ) return std::vector<std::pair<int64_t, int64_t>>{};
        const size_t cnt = w.GetFrameCount( *fd );
        std::vector<std::pair<int64_t, int64_t>> result;
        result.reserve( cnt );
        for( size_t i = 0; i < cnt; ++i )
            result.emplace_back( w.GetFrameBegin( *fd, i ), w.GetFrameEnd( *fd, i ) );
        return result;
    } ).def( "get_frame_times", []( const Worker& w ) {
        auto* fd = w.GetFramesBase();
        if( !fd ) return std::vector<int64_t>{};
        const size_t cnt = w.GetFrameCount( *fd );
        std::vector<int64_t> times;
        times.reserve( cnt );
        for( size_t i = 0; i < cnt; ++i )
            times.push_back( w.GetFrameTime( *fd, i ) );
        return times;
    } ).def( "get_frame_times_named", []( const Worker& w, const std::string& name ) {
        for( const auto* fd : w.GetFrames() )
        {
            if( !fd ) continue;
            if( w.GetString( fd->name ) == name )
            {
                const size_t cnt = w.GetFrameCount( *fd );
                std::vector<int64_t> times;
                times.reserve( cnt );
                for( size_t i = 0; i < cnt; ++i )
                    times.push_back( w.GetFrameTime( *fd, i ) );
                return times;
            }
        }
        return std::vector<int64_t>{};
    } ).def( "get_zones_in_frame", []( const Worker& w, size_t frameIdx ) {
            // Returns {zone_name: {count, total_ns}} for all CPU zones that STARTED within
            // the specified frame's time window. Uses sorted thread timelines for early exit.
        auto* fd = w.GetFramesBase();
        if( !fd || frameIdx >= (size_t)w.GetFrameCount( *fd ) ) return py::dict{};

        const int64_t frameStart = w.GetFrameBegin( *fd, (int)frameIdx );
        const int64_t frameEnd = w.GetFrameEnd( *fd, (int)frameIdx );

        struct Acc
        {
            int64_t total = 0;
            size_t count = 0;
        };
        std::unordered_map<int16_t, Acc> acc;

            // Returns false when a zone starts at or after frameEnd (prune signal
            // for sorted sibling lists). Uses a local struct instead of std::function
            // to avoid per-call heap allocation on the hot recursive path.
        struct Visitor
        {
            const Worker& w;
            std::unordered_map<int16_t, Acc>& acc;
            int64_t frameStart, frameEnd;

            bool operator()( const ZoneEvent& z )
            {
                if( !z.IsEndValid() ) return true;
                const int64_t zs = z.Start();
                if( zs >= frameEnd ) return false;
                if( zs >= frameStart )
                {
                    auto& s = acc[z.SrcLoc()];
                    s.total += z.End() - zs;
                    s.count++;
                }
                if( z.HasChildren() && z.End() > frameStart )
                {
                    const auto& ch = w.GetZoneChildren( z.Child() );
                    if( ch.is_magic() )
                    {
                        for( const auto& c : *(const Vector<ZoneEvent>*)&ch )
                        {
                            if( !( *this )( c ) ) break;
                        }
                    }
                    else
                    {
                        for( const auto& cptr : ch )
                        {
                            if( const ZoneEvent* c = cptr.get() )
                            {
                                if( !( *this )( *c ) ) break;
                            }
                        }
                    }
                }
                return true;
            }
        } visit{ w, acc, frameStart, frameEnd };

        for( const auto* td : w.GetThreadData() )
        {
            if( !td ) continue;
            if( td->timeline.is_magic() )
            {
                for( const auto& z : *(const Vector<ZoneEvent>*)&td->timeline )
                {
                    if( !visit( z ) ) break;
                }
            }
            else
            {
                for( const auto& zptr : td->timeline )
                {
                    const ZoneEvent* z = zptr.get();
                    if( z && !visit( *z ) ) break;
                }
            }
        }

        py::dict result;
        for( const auto& kv : acc )
        {
            py::dict d;
            d["count"] = kv.second.count;
            d["total_ns"] = kv.second.total;
            const char* zname = w.GetZoneName( w.GetSourceLocation( kv.first ) );
            result[zname] = d;
        }
        return result;
    }, "frame_idx"_a )

        // --- Messages ---
        .def( "get_messages", []( const Worker& w ) {
        const auto& msgs = w.GetMessages();
        std::vector<MessageInfo> result;
        result.reserve( msgs.size() );
        for( const auto& m_ptr : msgs )
        {
            const auto& msg = *m_ptr;
            result.push_back( MessageInfo{
                msg.time,
                std::string( w.GetString( msg.ref ) ),
                msg.color,
                (uint64_t)msg.thread } );
        }
        return result;
    } )

        // --- Plots ---
        .def( "get_plots", []( const Worker& w ) {
        static const char* plotTypeStr[] = { "User", "Memory", "SysTime", "Power" };
        std::vector<PlotSummary> result;
        for( const auto* pd : w.GetPlots() )
        {
            if( !pd ) continue;
            const size_t cnt = pd->data.size();
            const std::string name = w.GetString( pd->name );
            const char* typeStr = (uint8_t)pd->type < 4 ? plotTypeStr[(uint8_t)pd->type] : "Unknown";
            result.push_back( PlotSummary{
                name, pd->min, pd->max, pd->sum,
                cnt, cnt ? pd->sum / cnt : 0.0,
                std::string( typeStr ) } );
        }
        return result;
    } )

        // --- Memory pools ---
        .def( "get_memory_pools", []( const Worker& w ) {
        std::vector<MemPoolSummary> result;
        for( const auto& kv : w.GetMemNameMap() )
        {
            const MemData* md = kv.second;
            const std::string name = kv.first == 0 ? "(default)" : std::string( w.GetString( kv.first ) );
            result.push_back( MemPoolSummary{
                name, md->high, md->low, md->usage, md->data.size() } );
        }
        return result;
    } )

        // --- Locks ---
        .def( "get_locks", []( const Worker& w ) {
        std::vector<LockSummary> result;
        for( const auto& kv : w.GetLockMap() )
        {
            const LockMap* lm = kv.second;
            if( !lm || !lm->valid ) continue;
            std::string name;
            if( lm->customName.Active() )
                name = w.GetString( lm->customName );
            else
                name = w.GetZoneName( w.GetSourceLocation( lm->srcloc ) );
            const char* typeStr = lm->type == LockType::Lockable ? "Lockable" : "SharedLockable";
            result.push_back( LockSummary{
                name,
                lm->isContended,
                std::string( typeStr ),
                lm->timeAnnounce,
                lm->timeTerminate,
                lm->threadList } );
        }
        return result;
    } )

        // --- GPU contexts ---
        .def( "get_gpu_contexts", []( const Worker& w ) {
        static const char* gpuTypeStr[] = {
            "Invalid", "OpenGL", "Vulkan", "OpenCL", "Direct3D12", "Direct3D11", "Metal", "Custom", "CUDA", "Rocprof" };
        std::vector<GpuContextSummary> result;
        for( const auto* ctx : w.GetGpuData() )
        {
            if( !ctx ) continue;
            const std::string name = ctx->name.Active() ? w.GetString( ctx->name ) : "";
            const uint8_t typeIdx = (uint8_t)ctx->type;
            const char* typeStr = typeIdx < 10 ? gpuTypeStr[typeIdx] : "Unknown";
            result.push_back( GpuContextSummary{
                name, ctx->count, std::string( typeStr ), ctx->thread } );
        }
        return result;
    } )

        // --- Threads ---
        .def( "get_threads", []( const Worker& w ) {
            // Returns list of dicts to avoid raw-pointer pybind11 ownership issues
        py::list result;
        for( const auto& t : w.GetThreadData() )
        {
            if( !t ) continue;
            py::dict d;
            d["id"] = t->id;
            d["count"] = t->count;
            d["is_fiber"] = (bool)t->isFiber;
            d["name"] = std::string( w.GetThreadName( t->id ) );
            result.append( d );
        }
        return result;
    } ).def( "get_thread_name", []( const Worker& w, uint64_t tid ) {
        return w.GetThreadName( tid );
    } )

        // --- Connection control ---
        .def( "is_connected", &Worker::IsConnected )
        .def( "shutdown", &Worker::Shutdown )
        .def( "disconnect", &Worker::Disconnect );

    // -------------------------------------------------------------------------
    // FileRead
    // -------------------------------------------------------------------------
    m.def( "open_file", []( const char* path ) -> std::shared_ptr<FileRead> {
        auto f = FileRead::Open( path );
        if( !f ) throw std::runtime_error( "Could not open file" );
        return std::shared_ptr<FileRead>( f );
    } );

    py::class_<FileRead, std::shared_ptr<FileRead>>( m, "FileRead" );

    m.def( "create_worker_from_file", []( std::shared_ptr<FileRead> f ) {
        return std::make_unique<Worker>( *f );
    } );
}

} // namespace tracy
