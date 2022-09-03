#ifndef __TRACYUTILITY_HPP__
#define __TRACYUTILITY_HPP__

#include <stdint.h>

#include "imgui.h"
#include "TracyEvent.hpp"

namespace tracy
{

class Worker;

enum class ShortenName : uint8_t
{
    Never,
    Always,
    OnlyNormalize,
    NoSpace,
    NoSpaceAndNormalize,
};

const char* ShortenZoneName( ShortenName type, const char* name, ImVec2& tsz, float zsz );
void TooltipNormalizedName( const char* name, const char* normalized );

static inline const char* ShortenZoneName( ShortenName type, const char* name ) { ImVec2 tsz = {}; return ShortenZoneName( type, name, tsz, 0 ); }

uint32_t GetThreadColor( uint64_t thread, int depth, bool dynamic );
uint32_t GetPlotColor( const PlotData& plot, const Worker& worker );
const char* FormatPlotValue( double val, PlotValueFormatting format );

}

#endif
