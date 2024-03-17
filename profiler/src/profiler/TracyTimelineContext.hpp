#ifndef __TRACYTIMELINECONTEXT_HPP__
#define __TRACYTIMELINECONTEXT_HPP__

#include <stdint.h>

#include "imgui.h"

namespace tracy
{

struct TimelineContext
{
    float w, ty, sty, scale;
    float yMin, yMax;
    double pxns, nspx;
    int64_t vStart, vEnd;
    ImVec2 wpos;
    bool hover;
};

}

#endif
