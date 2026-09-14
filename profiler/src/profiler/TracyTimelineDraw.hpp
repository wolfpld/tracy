#ifndef __TRACYTIMELINEDRAW_HPP__
#define __TRACYTIMELINEDRAW_HPP__

#include <stdint.h>

#include "TracyEvent.hpp"
#include "TracyLocks.hpp"
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
    uint32_t inheritedColor;
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


enum class SampleType
{
    Own,
    External,
    Kernel
};

struct SamplesDraw
{
    uint32_t num;
    uint32_t idx;
    SampleType type;
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



struct LockDrawItem
{
    int64_t t1;
    uint8_t state;
    uint32_t num;
    const LockSegment* seg;
};

struct LockDraw
{
    uint32_t id;
    bool forceDraw;
    uint16_t thread;
    std::vector<LockDrawItem> data;
};

struct LockHighlight
{
    int64_t id;
    int64_t begin;
    int64_t end;
    uint16_t thread;
    bool blocked;
};

}

#endif
