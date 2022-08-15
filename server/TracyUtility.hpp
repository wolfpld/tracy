#ifndef __TRACYUTILITY_HPP__
#define __TRACYUTILITY_HPP__

#include <stdint.h>

#include "imgui.h"

namespace tracy
{

enum class ShortenName : uint8_t
{
    Never,
    Always,
    OnlyNormalize,
    NoSpace,
    NoSpaceAndNormalize,
};

const char* ShortenZoneName( ShortenName type, const char* name, ImVec2& tsz, float zsz );

static inline const char* ShortenZoneName( ShortenName type, const char* name ) { ImVec2 tsz = {}; return ShortenZoneName( type, name, tsz, 0 ); }

}

#endif
