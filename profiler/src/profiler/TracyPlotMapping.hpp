#ifndef __TRACYPLOTMAPPING_HPP__
#define __TRACYPLOTMAPPING_HPP__

#include <math.h>
#include <stdint.h>

namespace tracy
{

// To add a mapping: append an enum value (before Count), then extend PlotMappingName() and MapPlotValue().
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

}

#endif
