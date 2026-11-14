#ifndef __TRACYPLOTMAPPING_HPP__
#define __TRACYPLOTMAPPING_HPP__

#include <algorithm>
#include <float.h>
#include <math.h>
#include <stdint.h>

namespace tracy
{

// To add a mapping: append an enum value (before Count), then extend PlotMappingName(), MapPlotValue() and, optionally, ForEachPlotTick().
// Mappings must be strictly monotonic increasing and defined for all finite doubles.
enum class PlotMapping : uint8_t
{
    Linear,
    SymLog,
    Count
};

static inline const char* PlotMappingName( PlotMapping mapping )
{
    switch( mapping )
    {
    case PlotMapping::Linear: return "Linear";
    case PlotMapping::SymLog: return "Logarithmic";
    default: return "";
    }
}

static inline double MapPlotValue( PlotMapping mapping, double v )
{
    switch( mapping )
    {
    case PlotMapping::SymLog:
        // sign(v) * log10( 1 + |v| ), computed via log1p to stay accurate for tiny |v|
        // TODO(slomp): nearly linear for sub-1 floating-point data; consider scaling by a data-derived constant
        return copysign( log1p( fabs( v ) ) * 0.43429448190325176, v );
    case PlotMapping::Linear:
    default:
        return v;
    }
}

// Calls f( value ) for each reference value within [min, max], in ascending order.
template<typename F>
static inline void ForEachPlotTick( PlotMapping mapping, double min, double max, F&& f )
{
    switch( mapping )
    {
    case PlotMapping::SymLog:
    {
        // floor( log10( v ) ) for v >= 1, else -1 (also for NaN); clamped so inf can't overflow the int
        const auto decade = [] ( double v ) { return v >= 1 ? int( log10( std::min( v, DBL_MAX ) ) ) : -1; };
        const auto emit = [&] ( double v ) { if( v >= min && v <= max ) f( v ); };
        for( int k = decade( -min ); k >= std::max( decade( -max ), 0 ); k-- ) emit( -pow( 10.0, k ) );
        if( min <= 0 && max >= 0 ) f( 0.0 );
        for( int k = std::max( decade( min ), 0 ); k <= decade( max ); k++ ) emit( pow( 10.0, k ) );
        break;
    }
    case PlotMapping::Linear:
    default:
        break;
    }
}

}

#endif
