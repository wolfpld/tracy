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
    uint32_t num;
};


enum class ContextSwitchDrawType : uint8_t
{
    Waiting,
    Folded,
    Running
};

struct ContextSwitchDraw
{
    ContextSwitchDrawType type;
    uint32_t idx;
    uint32_t data;                  // Folded: number of items -OR- Waiting: wait stack
};


struct SamplesDraw
{
    uint32_t num;
    uint32_t idx;
};


struct MessagesDraw
{
    short_ptr<MessageData> msg;
    bool highlight;
    uint32_t num;
};


struct CpuUsageDraw
{
    int own;
    int other;
};


struct CpuCtxDraw
{
    uint32_t idx;
    uint32_t num;
};


}

#endif
