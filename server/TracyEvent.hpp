#ifndef __TRACYEVENT_HPP__
#define __TRACYEVENT_HPP__

#include "TracyVector.hpp"

namespace tracy
{

struct TextData
{
    const char* userText;
    uint64_t zoneName;      // ptr
};

struct Event
{
    int64_t start;
    int64_t end;
    uint64_t srcloc;
    int8_t cpu_start;
    int8_t cpu_end;

    TextData* text;
    Event* parent;
    Vector<Event*> child;
};

enum { EventSize = sizeof( Event ) };


struct LockEvent
{
    uint64_t srcloc;
};

enum { LockEventSize = sizeof( LockEvent ) };

}

#endif
