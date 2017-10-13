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
    LockWait,
    LockObtain,
    LockRelease,
    LockMark,
    PlotData,
    NUM_TYPES
};

#pragma pack( 1 )

struct QueueZoneBegin
{
    int64_t time;
    uint64_t thread;
    uint64_t srcloc;    // ptr
    uint32_t cpu;
};

struct QueueZoneEnd
{
    int64_t time;
    uint64_t thread;
    uint32_t cpu;
};

struct QueueStringTransfer
{
    uint64_t ptr;
};

struct QueueFrameMark
{
    int64_t time;
};

struct QueueSourceLocation
{
    uint64_t ptr;
    uint64_t function;  // ptr
    uint64_t file;      // ptr
    uint32_t line;
    uint32_t color;
};

struct QueueZoneText
{
    uint64_t thread;
    uint64_t text;      // ptr
};

struct QueueZoneName
{
    uint64_t thread;
    uint64_t name;      // ptr
};

struct QueueLockWait
{
    uint64_t id;
    int64_t time;
    uint64_t thread;
    uint64_t lckloc;    // ptr
};

struct QueueLockObtain
{
    uint64_t id;
    int64_t time;
    uint64_t thread;
};

struct QueueLockRelease
{
    uint64_t id;
    int64_t time;
    uint64_t thread;
};

struct QueueLockMark
{
    uint64_t id;
    uint64_t thread;
    uint64_t srcloc;    // ptr
};

enum class PlotDataType : uint8_t
{
    Float,
    Double,
    Int
};

struct QueuePlotData
{
    uint64_t name;      // ptr
    int64_t time;
    PlotDataType type;
    union
    {
        double d;
        float f;
        int64_t i;
    } data;
};

struct QueueHeader
{
    union
    {
        QueueType type;
        uint8_t idx;
    };
};

struct QueueItem
{
    QueueHeader hdr;
    union
    {
        QueueZoneBegin zoneBegin;
        QueueZoneEnd zoneEnd;
        QueueStringTransfer stringTransfer;
        QueueFrameMark frameMark;
        QueueSourceLocation srcloc;
        QueueZoneText zoneText;
        QueueZoneName zoneName;
        QueueLockWait lockWait;
        QueueLockObtain lockObtain;
        QueueLockRelease lockRelease;
        QueueLockMark lockMark;
        QueuePlotData plotData;
    };
};

#pragma pack()

enum { QueueItemSize = sizeof( QueueItem ) };

static const size_t QueueDataSize[] = {
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),
    sizeof( QueueHeader ) + sizeof( QueueZoneEnd ),
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // string data
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // thread name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // custom string data
    sizeof( QueueHeader ) + sizeof( QueueFrameMark ),
    sizeof( QueueHeader ) + sizeof( QueueSourceLocation ),
    sizeof( QueueHeader ) + sizeof( QueueZoneText ),
    sizeof( QueueHeader ) + sizeof( QueueZoneName ),
    sizeof( QueueHeader ) + sizeof( QueueLockWait ),
    sizeof( QueueHeader ) + sizeof( QueueLockObtain ),
    sizeof( QueueHeader ) + sizeof( QueueLockRelease ),
    sizeof( QueueHeader ) + sizeof( QueueLockMark ),
    sizeof( QueueHeader ) + sizeof( QueuePlotData ),
};

static_assert( sizeof( QueueDataSize ) / sizeof( size_t ) == (uint8_t)QueueType::NUM_TYPES, "QueueDataSize mismatch" );
static_assert( sizeof( void* ) <= sizeof( uint64_t ), "Pointer size > 8 bytes" );

};

#endif
