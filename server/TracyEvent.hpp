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

#pragma pack( 1 )

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
    enum class Type : uint8_t
    {
        Wait,
        Obtain,
        Release
    };

    int64_t time;
    uint64_t thread;
    uint64_t srcloc;
    uint8_t lockCount;
    uint8_t waitCount;
    Type type;
};

enum { LockEventSize = sizeof( LockEvent ) };

#pragma pack()

}

#endif
