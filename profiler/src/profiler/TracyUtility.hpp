#ifndef __TRACYUTILITY_HPP__
#define __TRACYUTILITY_HPP__

#include <stdint.h>
#include <string>
#include <vector>

#include "imgui.h"
#include "../server/TracyEvent.hpp"

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

std::vector<std::string> SplitLines( const char* data, size_t sz );

bool IsFrameExternal( const char* filename, const char* image );

}

#endif
