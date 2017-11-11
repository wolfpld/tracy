#ifndef __TRACYEVENT_HPP__
#define __TRACYEVENT_HPP__

#include <limits>

#include "TracyVector.hpp"

namespace tracy
{

#pragma pack( 1 )

struct StringRef
{
    enum Type { Ptr, Idx };

    StringRef() {}
    StringRef( Type t, uint64_t data )
        : isidx( t == Idx )
    {
        if( isidx )
        {
            stridx = (uint32_t)data;
        }
        else
        {
            strptr = data;
        }
    }

    union
    {
        uint64_t strptr;
        uint32_t stridx;
    };
    bool isidx;
};

struct TextData
{
    const char* userText;
    uint64_t zoneName;      // ptr
};

struct SourceLocation
{
    StringRef function;
    StringRef file;
    uint32_t line;
    uint32_t color;
};

enum { SourceLocationSize = sizeof( SourceLocation ) };


struct ZoneEvent
{
    int64_t start;
    int64_t end;
    int32_t srcloc;
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
    int32_t srcloc;
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
