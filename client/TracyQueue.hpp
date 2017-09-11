#ifndef __TRACYQUEUE_HPP__
#define __TRACYQUEUE_HPP__

#include <stdint.h>

namespace tracy
{

enum class QueueType : uint8_t
{
    ZoneBegin,
    ZoneEnd
};

#pragma pack( 1 )

struct QueueZoneBegin
{
    uint64_t id;
    const char* filename;
    const char* function;
    uint32_t line;
};

struct QueueZoneEnd
{
    uint64_t id;
};

struct QueueHeader
{
    QueueType type;
    int64_t time;
};

struct QueueItem
{
    QueueHeader hdr;
    union
    {
        QueueZoneBegin zoneBegin;
        QueueZoneEnd zoneEnd;
    };
};

#pragma pack()

enum { QueueItemSize = sizeof( QueueItem ) };

};

#endif
