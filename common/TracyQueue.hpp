#ifndef __TRACYQUEUE_HPP__
#define __TRACYQUEUE_HPP__

#include <stdint.h>

namespace tracy
{

enum class QueueType : uint8_t
{
    ZoneText,
    ZoneName,
    Message,
    ZoneBeginAllocSrcLoc,
    ZoneBeginAllocSrcLocCallstack,
    CallstackMemory,
    Callstack,
    CallstackAlloc,
    Terminate,
    KeepAlive,
    Crash,
    CrashReport,
    ZoneBegin,
    ZoneBeginCallstack,
    ZoneEnd,
    ZoneValidation,
    FrameMarkMsg,
    FrameMarkMsgStart,
    FrameMarkMsgEnd,
    SourceLocation,
    LockAnnounce,
    LockTerminate,
    LockWait,
    LockObtain,
    LockRelease,
    LockSharedWait,
    LockSharedObtain,
    LockSharedRelease,
    LockMark,
    PlotData,
    MessageLiteral,
    GpuNewContext,
    GpuZoneBegin,
    GpuZoneBeginCallstack,
    GpuZoneEnd,
    GpuTime,
    MemAlloc,
    MemFree,
    MemAllocCallstack,
    MemFreeCallstack,
    CallstackFrameSize,
    CallstackFrame,
    SysTimeReport,
    StringData,
    ThreadName,
    CustomStringData,
    PlotName,
    SourceLocationPayload,
    CallstackPayload,
    CallstackAllocPayload,
    FrameName,
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

struct QueueZoneValidation
{
    uint64_t thread;
    uint32_t id;
};

struct QueueStringTransfer
{
    uint64_t ptr;
};

struct QueueFrameMark
{
    int64_t time;
    uint64_t name;      // ptr
};

struct QueueSourceLocation
{
    uint64_t name;
    uint64_t function;  // ptr
    uint64_t file;      // ptr
    uint32_t line;
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

struct QueueZoneText
{
    uint64_t thread;
    uint64_t text;      // ptr
};

enum class LockType : uint8_t
{
    Lockable,
    SharedLockable
};

struct QueueLockAnnounce
{
    uint32_t id;
    int64_t time;
    uint64_t lckloc;    // ptr
    LockType type;
};

struct QueueLockTerminate
{
    uint32_t id;
    int64_t time;
    LockType type;
};

struct QueueLockWait
{
    uint32_t id;
    int64_t time;
    uint64_t thread;
    LockType type;
};

struct QueueLockObtain
{
    uint32_t id;
    int64_t time;
    uint64_t thread;
};

struct QueueLockRelease
{
    uint32_t id;
    int64_t time;
    uint64_t thread;
};

struct QueueLockMark
{
    uint32_t id;
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

struct QueueMessage
{
    int64_t time;
    uint64_t thread;
    uint64_t text;      // ptr
};

struct QueueGpuNewContext
{
    int64_t cpuTime;
    int64_t gpuTime;
    uint64_t thread;
    float period;
    uint8_t context;
    uint8_t accuracyBits;
};

struct QueueGpuZoneBegin
{
    int64_t cpuTime;
    uint64_t srcloc;
    uint64_t thread;
    uint16_t queryId;
    uint8_t context;
};

struct QueueGpuZoneEnd
{
    int64_t cpuTime;
    uint16_t queryId;
    uint8_t context;
};

struct QueueGpuTime
{
    int64_t gpuTime;
    uint16_t queryId;
    uint8_t context;
};

struct QueueMemAlloc
{
    int64_t time;
    uint64_t thread;
    uint64_t ptr;
    char size[6];
};

struct QueueMemFree
{
    int64_t time;
    uint64_t thread;
    uint64_t ptr;
};

struct QueueCallstackMemory
{
    uint64_t ptr;
};

struct QueueCallstack
{
    uint64_t ptr;
    uint64_t thread;
};

struct QueueCallstackAlloc
{
    uint64_t ptr;
    uint64_t nativePtr;
    uint64_t thread;
};

struct QueueCallstackFrameSize
{
    uint64_t ptr;
    uint8_t size;
};

struct QueueCallstackFrame
{
    uint64_t name;
    uint64_t file;
    uint32_t line;
};

struct QueueCrashReport
{
    int64_t time;
    uint64_t thread;
    uint64_t text;      // ptr
};

struct QueueSysTime
{
    int64_t time;
    float sysTime;
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
        QueueZoneValidation zoneValidation;
        QueueStringTransfer stringTransfer;
        QueueFrameMark frameMark;
        QueueSourceLocation srcloc;
        QueueZoneText zoneText;
        QueueLockAnnounce lockAnnounce;
        QueueLockTerminate lockTerminate;
        QueueLockWait lockWait;
        QueueLockObtain lockObtain;
        QueueLockRelease lockRelease;
        QueueLockMark lockMark;
        QueuePlotData plotData;
        QueueMessage message;
        QueueGpuNewContext gpuNewContext;
        QueueGpuZoneBegin gpuZoneBegin;
        QueueGpuZoneEnd gpuZoneEnd;
        QueueGpuTime gpuTime;
        QueueMemAlloc memAlloc;
        QueueMemFree memFree;
        QueueCallstackMemory callstackMemory;
        QueueCallstack callstack;
        QueueCallstackAlloc callstackAlloc;
        QueueCallstackFrameSize callstackFrameSize;
        QueueCallstackFrame callstackFrame;
        QueueCrashReport crashReport;
        QueueSysTime sysTime;
    };
};

#pragma pack()

enum { QueueItemSize = sizeof( QueueItem ) };

static const size_t QueueDataSize[] = {
    sizeof( QueueHeader ) + sizeof( QueueZoneText ),
    sizeof( QueueHeader ) + sizeof( QueueZoneText ),        // zone name
    sizeof( QueueHeader ) + sizeof( QueueMessage ),
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),       // allocated source location
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),       // allocated source location, callstack
    sizeof( QueueHeader ) + sizeof( QueueCallstackMemory ),
    sizeof( QueueHeader ) + sizeof( QueueCallstack ),
    sizeof( QueueHeader ) + sizeof( QueueCallstackAlloc ),
    // above items must be first
    sizeof( QueueHeader ),                                  // terminate
    sizeof( QueueHeader ),                                  // keep alive
    sizeof( QueueHeader ),                                  // crash
    sizeof( QueueHeader ) + sizeof( QueueCrashReport ),
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),       // callstack
    sizeof( QueueHeader ) + sizeof( QueueZoneEnd ),
    sizeof( QueueHeader ) + sizeof( QueueZoneValidation ),
    sizeof( QueueHeader ) + sizeof( QueueFrameMark ),       // continuous frames
    sizeof( QueueHeader ) + sizeof( QueueFrameMark ),       // start
    sizeof( QueueHeader ) + sizeof( QueueFrameMark ),       // end
    sizeof( QueueHeader ) + sizeof( QueueSourceLocation ),
    sizeof( QueueHeader ) + sizeof( QueueLockAnnounce ),
    sizeof( QueueHeader ) + sizeof( QueueLockTerminate ),
    sizeof( QueueHeader ) + sizeof( QueueLockWait ),
    sizeof( QueueHeader ) + sizeof( QueueLockObtain ),
    sizeof( QueueHeader ) + sizeof( QueueLockRelease ),
    sizeof( QueueHeader ) + sizeof( QueueLockWait ),
    sizeof( QueueHeader ) + sizeof( QueueLockObtain ),
    sizeof( QueueHeader ) + sizeof( QueueLockRelease ),
    sizeof( QueueHeader ) + sizeof( QueueLockMark ),
    sizeof( QueueHeader ) + sizeof( QueuePlotData ),
    sizeof( QueueHeader ) + sizeof( QueueMessage ),         // literal
    sizeof( QueueHeader ) + sizeof( QueueGpuNewContext ),
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBegin ),
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBegin ),    // callstack
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneEnd ),
    sizeof( QueueHeader ) + sizeof( QueueGpuTime ),
    sizeof( QueueHeader ) + sizeof( QueueMemAlloc ),
    sizeof( QueueHeader ) + sizeof( QueueMemFree ),
    sizeof( QueueHeader ) + sizeof( QueueMemAlloc ),        // callstack
    sizeof( QueueHeader ) + sizeof( QueueMemFree ),         // callstack
    sizeof( QueueHeader ) + sizeof( QueueCallstackFrameSize ),
    sizeof( QueueHeader ) + sizeof( QueueCallstackFrame ),
    sizeof( QueueHeader ) + sizeof( QueueSysTime ),
    // keep all QueueStringTransfer below
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // string data
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // thread name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // custom string data
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // plot name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // allocated source location payload
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // callstack payload
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // callstack alloc payload
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // frame name
};

static_assert( QueueItemSize == 32, "Queue item size not 32 bytes" );
static_assert( sizeof( QueueDataSize ) / sizeof( size_t ) == (uint8_t)QueueType::NUM_TYPES, "QueueDataSize mismatch" );
static_assert( sizeof( void* ) <= sizeof( uint64_t ), "Pointer size > 8 bytes" );
static_assert( sizeof( void* ) == sizeof( uintptr_t ), "Pointer size != uintptr_t" );

};

#endif
