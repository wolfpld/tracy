#ifndef __TRACYQUEUE_HPP__
#define __TRACYQUEUE_HPP__

#include <stdint.h>

namespace tracy
{

enum class QueueType : uint8_t
{
    ZoneBegin,
    ZoneEnd,
    StringData,
    NUM_TYPES
};

#pragma pack( 1 )

struct QueueZoneBegin
{
    int64_t time;
    uint64_t filename;  // ptr
    uint64_t function;  // ptr
    uint32_t line;
};

struct QueueZoneEnd
{
    int64_t time;
};

struct QueueHeader
{
    union
    {
        QueueType type;
        uint8_t idx;
    };
    uint64_t id;
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

static const size_t QueueDataSize[] = {
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),
    sizeof( QueueHeader ) + sizeof( QueueZoneEnd ),
    sizeof( QueueHeader ),
};

static_assert( sizeof( QueueDataSize ) / sizeof( size_t ) == (uint8_t)QueueType::NUM_TYPES, "QueueDataSize mismatch" );
static_assert( sizeof( void* ) <= sizeof( uint64_t ), "Pointer size > 8 bytes" );

};

#endif
