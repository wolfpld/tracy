#ifndef __TRACYTIMELINEDRAW_HPP__
#define __TRACYTIMELINEDRAW_HPP__

#include <stdint.h>

#include "TracyEvent.hpp"
#include "TracyShortPtr.hpp"

namespace tracy
{

enum class TimelineDrawType : uint8_t
{
    Folded,
    Zone,
    GhostFolded,
    Ghost
};

struct TimelineDraw
{
    TimelineDrawType type;
    uint16_t depth;
    short_ptr<void*> ev;
    Int48 rend;
    int num;
};

}

#endif
