#ifndef __TRACYEVENT_HPP__
#define __TRACYEVENT_HPP__

#include <limits>

#include "TracyVector.hpp"

namespace tracy
{

struct TextData
{
    const char* userText;
    uint64_t zoneName;      // ptr
};

#pragma pack( 1 )

struct ZoneEvent
{
    int64_t start;
    int64_t end;
    uint32_t srcloc;
    int8_t cpu_start;
    int8_t cpu_end;

    int32_t text;
    Vector<ZoneEvent*> child;
};

enum { ZoneEventSize = sizeof( ZoneEvent ) };


struct LockEvent
{
    enum class Type : uint8_t
    {
        Wait,
        Obtain,
        Release
    };

    int64_t time;
    uint32_t srcloc;
    uint64_t waitList;
    uint16_t thread         : 6;
    uint16_t lockingThread  : 6;
    uint16_t type           : 2;
    uint8_t lockCount;
};

enum { LockEventSize = sizeof( LockEvent ) };

enum { MaxLockThreads = sizeof( LockEvent::waitList ) * 8 };
static_assert( std::numeric_limits<decltype(LockEvent::lockCount)>::max() >= MaxLockThreads, "Not enough space for lock count." );

#pragma pack()

}

#endif
