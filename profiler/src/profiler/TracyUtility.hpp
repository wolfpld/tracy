#ifndef __TRACYUTILITY_HPP__
#define __TRACYUTILITY_HPP__

#include <stdint.h>
#include <string>
#include <vector>

#include "imgui.h"
#include "../server/TracyEvent.hpp"

namespace tracy
{

struct CallstackFrameData;
class View;
class Worker;

struct Range
{
    void StartFrame() { hiMin = hiMax = false; }

    int64_t min = 0;
    int64_t max = 0;
    bool active = false;
    bool hiMin = false;
    bool hiMax = false;
    bool modMin = false;
    bool modMax = false;
};

struct RangeSlim
{
    bool operator==( const Range& other ) const { return other.active == active && other.min == min && other.max == max; }
    bool operator!=( const Range& other ) const { return !(*this == other); }
    void operator=( const Range& other ) { active = other.active; min = other.min; max = other.max; }

    int64_t min, max;
    bool active = false;
};

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

void PrintLocalStack( const CallstackFrameData* frame, const Worker& worker, const View& view );

}

#endif
