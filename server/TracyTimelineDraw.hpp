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


enum class ContextSwitchDrawType : uint8_t
{
    Waiting,
    FoldedOne,
    FoldedMulti,
    Running
};

struct ContextSwitchDrawFolded
{
    Int48 rend;
    int num;
};

struct ContextSwitchDrawWaiting
{
    short_ptr<ContextSwitchData> prev;
    Int24 waitStack;
};

struct ContextSwitchDraw
{
    ContextSwitchDrawType type;
    short_ptr<ContextSwitchData> ev;
    float minpx;
    union
    {
        ContextSwitchDrawFolded folded;
        ContextSwitchDrawWaiting waiting;
    };
};

}

#endif
