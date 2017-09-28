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
    ThreadName,
    CustomStringData,
    FrameMarkMsg,
    SourceLocation,
    ZoneText,
    ZoneName,
    NUM_TYPES
};

#pragma pack( 1 )

struct QueueZoneBegin
{
    int64_t time;
    uint64_t srcloc;    // ptr
    uint64_t thread;
};

struct QueueZoneEnd
{
    int64_t time;
};

struct QueueSourceLocation
{
    uint64_t function;  // ptr
    uint64_t file;      // ptr
    uint32_t line;
    uint32_t color;
};

struct QueueZoneText
{
    uint64_t text;      // ptr
};

struct QueueZoneName
{
    uint64_t name;      // ptr
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
        QueueSourceLocation srcloc;
        QueueZoneText zoneText;
        QueueZoneName zoneName;
    };
};

#pragma pack()

enum { QueueItemSize = sizeof( QueueItem ) };

static const size_t QueueDataSize[] = {
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),
    sizeof( QueueHeader ) + sizeof( QueueZoneEnd ),
    sizeof( QueueHeader ),  // string data
    sizeof( QueueHeader ),  // thread name
    sizeof( QueueHeader ),  // custom string data
    sizeof( QueueHeader ),  // frame mark
    sizeof( QueueHeader ) + sizeof( QueueSourceLocation ),
    sizeof( QueueHeader ) + sizeof( QueueZoneText ),
    sizeof( QueueHeader ) + sizeof( QueueZoneName ),
};

static_assert( sizeof( QueueDataSize ) / sizeof( size_t ) == (uint8_t)QueueType::NUM_TYPES, "QueueDataSize mismatch" );
static_assert( sizeof( void* ) <= sizeof( uint64_t ), "Pointer size > 8 bytes" );

};

#endif
