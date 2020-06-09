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
    MessageColor,
    MessageCallstack,
    MessageColorCallstack,
    MessageAppInfo,
    ZoneBeginAllocSrcLoc,
    ZoneBeginAllocSrcLocLean,
    ZoneBeginAllocSrcLocCallstack,
    ZoneBeginAllocSrcLocCallstackLean,
    CallstackMemory,
    CallstackMemoryLean,
    Callstack,
    CallstackLean,
    CallstackAlloc,
    CallstackAllocLean,
    CallstackSample,
    CallstackSampleLean,
    FrameImage,
    FrameImageLean,
    ZoneBegin,
    ZoneBeginCallstack,
    ZoneEnd,
    LockWait,
    LockObtain,
    LockRelease,
    LockSharedWait,
    LockSharedObtain,
    LockSharedRelease,
    LockName,
    MemAlloc,
    MemFree,
    MemAllocCallstack,
    MemFreeCallstack,
    GpuZoneBegin,
    GpuZoneBeginCallstack,
    GpuZoneEnd,
    GpuZoneBeginSerial,
    GpuZoneBeginCallstackSerial,
    GpuZoneEndSerial,
    PlotData,
    ContextSwitch,
    ThreadWakeup,
    GpuTime,
    Terminate,
    KeepAlive,
    ThreadContext,
    Crash,
    CrashReport,
    ZoneValidation,
    ZoneValue,
    FrameMarkMsg,
    FrameMarkMsgStart,
    FrameMarkMsgEnd,
    SourceLocation,
    LockAnnounce,
    LockTerminate,
    LockMark,
    MessageLiteral,
    MessageLiteralColor,
    MessageLiteralCallstack,
    MessageLiteralColorCallstack,
    GpuNewContext,
    CallstackFrameSize,
    CallstackFrame,
    SymbolInformation,
    CodeInformation,
    SysTimeReport,
    TidToPid,
    PlotConfig,
    ParamSetup,
    ParamPingback,
    CpuTopology,
    StringData,
    ThreadName,
    CustomStringData,
    PlotName,
    SourceLocationPayload,
    CallstackPayload,
    CallstackAllocPayload,
    FrameName,
    FrameImageData,
    ExternalName,
    ExternalThreadName,
    SymbolCode,
    NUM_TYPES
};

#pragma pack( 1 )

struct QueueThreadContext
{
    uint64_t thread;
};

struct QueueZoneBeginLean
{
    int64_t time;
};

struct QueueZoneBegin : public QueueZoneBeginLean
{
    uint64_t srcloc;    // ptr
};

struct QueueZoneEnd
{
    int64_t time;
};

struct QueueZoneValidation
{
    uint32_t id;
};

struct QueueZoneValue
{
    uint64_t value;
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

struct QueueFrameImageLean
{
    uint64_t frame;
    uint16_t w;
    uint16_t h;
    uint8_t flip;
};

struct QueueFrameImage : public QueueFrameImageLean
{
    uint64_t image;     // ptr
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
    uint64_t thread;
    uint32_t id;
    int64_t time;
    LockType type;
};

struct QueueLockObtain
{
    uint64_t thread;
    uint32_t id;
    int64_t time;
};

struct QueueLockRelease
{
    uint64_t thread;
    uint32_t id;
    int64_t time;
};

struct QueueLockMark
{
    uint64_t thread;
    uint32_t id;
    uint64_t srcloc;    // ptr
};

struct QueueLockName
{
    uint32_t id;
    uint64_t name;      // ptr
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
    uint64_t text;      // ptr
};

struct QueueMessageColor : public QueueMessage
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

// Don't change order, only add new entries at the end, this is also used on trace dumps!
enum class GpuContextType : uint8_t
{
    Invalid,
    OpenGl,
    Vulkan,
    OpenCL,
    Direct3D12
};

struct QueueGpuNewContext
{
    int64_t cpuTime;
    int64_t gpuTime;
    uint64_t thread;
    float period;
    uint8_t context;
    uint8_t accuracyBits;
    GpuContextType type;
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
    uint64_t thread;
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
};

struct QueueCallstackAlloc
{
    uint64_t ptr;
    uint64_t nativePtr;
};

struct QueueCallstackSampleLean
{
    int64_t time;
    uint64_t thread;
};

struct QueueCallstackSample : public QueueCallstackSampleLean
{
    uint64_t ptr;
};

struct QueueCallstackFrameSize
{
    uint64_t ptr;
    uint8_t size;
    uint64_t imageName;
};

struct QueueCallstackFrame
{
    uint64_t name;
    uint64_t file;
    uint32_t line;
    uint64_t symAddr;
    char symLen[3];
};

struct QueueSymbolInformation
{
    uint64_t file;
    uint32_t line;
    uint64_t symAddr;
};

struct QueueCodeInformation
{
    uint64_t ptr;
    uint64_t file;
    uint32_t line;
};

struct QueueCrashReport
{
    int64_t time;
    uint64_t text;      // ptr
};

struct QueueSysTime
{
    int64_t time;
    float sysTime;
};

struct QueueContextSwitch
{
    int64_t time;
    uint64_t oldThread;
    uint64_t newThread;
    uint8_t cpu;
    uint8_t reason;
    uint8_t state;
};

struct QueueThreadWakeup
{
    int64_t time;
    uint64_t thread;
};

struct QueueTidToPid
{
    uint64_t tid;
    uint64_t pid;
};

enum class PlotFormatType : uint8_t
{
    Number,
    Memory,
    Percentage
};

struct QueuePlotConfig
{
    uint64_t name;      // ptr
    uint8_t type;
};

struct QueueParamSetup
{
    uint32_t idx;
    uint64_t name;      // ptr
    uint8_t isBool;
    int32_t val;
};

struct QueueCpuTopology
{
    uint32_t package;
    uint32_t core;
    uint32_t thread;
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
        QueueThreadContext threadCtx;
        QueueZoneBegin zoneBegin;
        QueueZoneBeginLean zoneBeginLean;
        QueueZoneEnd zoneEnd;
        QueueZoneValidation zoneValidation;
        QueueZoneValue zoneValue;
        QueueStringTransfer stringTransfer;
        QueueFrameMark frameMark;
        QueueFrameImage frameImage;
        QueueFrameImage frameImageLean;
        QueueSourceLocation srcloc;
        QueueZoneText zoneText;
        QueueLockAnnounce lockAnnounce;
        QueueLockTerminate lockTerminate;
        QueueLockWait lockWait;
        QueueLockObtain lockObtain;
        QueueLockRelease lockRelease;
        QueueLockMark lockMark;
        QueueLockName lockName;
        QueuePlotData plotData;
        QueueMessage message;
        QueueMessageColor messageColor;
        QueueGpuNewContext gpuNewContext;
        QueueGpuZoneBegin gpuZoneBegin;
        QueueGpuZoneEnd gpuZoneEnd;
        QueueGpuTime gpuTime;
        QueueMemAlloc memAlloc;
        QueueMemFree memFree;
        QueueCallstackMemory callstackMemory;
        QueueCallstack callstack;
        QueueCallstackAlloc callstackAlloc;
        QueueCallstackSample callstackSample;
        QueueCallstackSampleLean callstackSampleLean;
        QueueCallstackFrameSize callstackFrameSize;
        QueueCallstackFrame callstackFrame;
        QueueSymbolInformation symbolInformation;
        QueueCodeInformation codeInformation;
        QueueCrashReport crashReport;
        QueueSysTime sysTime;
        QueueContextSwitch contextSwitch;
        QueueThreadWakeup threadWakeup;
        QueueTidToPid tidToPid;
        QueuePlotConfig plotConfig;
        QueueParamSetup paramSetup;
        QueueCpuTopology cpuTopology;
    };
};
#pragma pack()


enum { QueueItemSize = sizeof( QueueItem ) };

static constexpr size_t QueueDataSize[] = {
    sizeof( QueueHeader ) + sizeof( QueueZoneText ),
    sizeof( QueueHeader ) + sizeof( QueueZoneText ),        // zone name
    sizeof( QueueHeader ) + sizeof( QueueMessage ),
    sizeof( QueueHeader ) + sizeof( QueueMessageColor ),
    sizeof( QueueHeader ) + sizeof( QueueMessage ),         // callstack
    sizeof( QueueHeader ) + sizeof( QueueMessageColor ),    // callstack
    sizeof( QueueHeader ) + sizeof( QueueMessage ),         // app info
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),       // allocated source location, not for network transfer
    sizeof( QueueHeader ) + sizeof( QueueZoneBeginLean ),   // lean allocated source location
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),       // allocated source location, callstack, not for network transfer
    sizeof( QueueHeader ) + sizeof( QueueZoneBeginLean ),   // lean allocated source location, callstack
    sizeof( QueueHeader ) + sizeof( QueueCallstackMemory ), // not for network transfer
    sizeof( QueueHeader ),                                  // lean callstack memory
    sizeof( QueueHeader ) + sizeof( QueueCallstack ),       // not for network transfer
    sizeof( QueueHeader ),                                  // lean callstack
    sizeof( QueueHeader ) + sizeof( QueueCallstackAlloc ),  // not for network transfer
    sizeof( QueueHeader ),                                  // lean callstack alloc
    sizeof( QueueHeader ) + sizeof( QueueCallstackSample ), // not for network transfer
    sizeof( QueueHeader ) + sizeof( QueueCallstackSampleLean ),
    sizeof( QueueHeader ) + sizeof( QueueFrameImage ),      // not for network transfer
    sizeof( QueueHeader ) + sizeof( QueueFrameImageLean ),
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),
    sizeof( QueueHeader ) + sizeof( QueueZoneBegin ),       // callstack
    sizeof( QueueHeader ) + sizeof( QueueZoneEnd ),
    sizeof( QueueHeader ) + sizeof( QueueLockWait ),
    sizeof( QueueHeader ) + sizeof( QueueLockObtain ),
    sizeof( QueueHeader ) + sizeof( QueueLockRelease ),
    sizeof( QueueHeader ) + sizeof( QueueLockWait ),        // shared
    sizeof( QueueHeader ) + sizeof( QueueLockObtain ),      // shared
    sizeof( QueueHeader ) + sizeof( QueueLockRelease ),     // shared
    sizeof( QueueHeader ) + sizeof( QueueLockName ),
    sizeof( QueueHeader ) + sizeof( QueueMemAlloc ),
    sizeof( QueueHeader ) + sizeof( QueueMemFree ),
    sizeof( QueueHeader ) + sizeof( QueueMemAlloc ),        // callstack
    sizeof( QueueHeader ) + sizeof( QueueMemFree ),         // callstack
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBegin ),
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBegin ),    // callstack
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneEnd ),
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBegin ),    // serial
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBegin ),    // serial, callstack
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneEnd ),      // serial
    sizeof( QueueHeader ) + sizeof( QueuePlotData ),
    sizeof( QueueHeader ) + sizeof( QueueContextSwitch ),
    sizeof( QueueHeader ) + sizeof( QueueThreadWakeup ),
    sizeof( QueueHeader ) + sizeof( QueueGpuTime ),
    // above items must be first
    sizeof( QueueHeader ),                                  // terminate
    sizeof( QueueHeader ),                                  // keep alive
    sizeof( QueueHeader ) + sizeof( QueueThreadContext ),
    sizeof( QueueHeader ),                                  // crash
    sizeof( QueueHeader ) + sizeof( QueueCrashReport ),
    sizeof( QueueHeader ) + sizeof( QueueZoneValidation ),
    sizeof( QueueHeader ) + sizeof( QueueZoneValue ),
    sizeof( QueueHeader ) + sizeof( QueueFrameMark ),       // continuous frames
    sizeof( QueueHeader ) + sizeof( QueueFrameMark ),       // start
    sizeof( QueueHeader ) + sizeof( QueueFrameMark ),       // end
    sizeof( QueueHeader ) + sizeof( QueueSourceLocation ),
    sizeof( QueueHeader ) + sizeof( QueueLockAnnounce ),
    sizeof( QueueHeader ) + sizeof( QueueLockTerminate ),
    sizeof( QueueHeader ) + sizeof( QueueLockMark ),
    sizeof( QueueHeader ) + sizeof( QueueMessage ),         // literal
    sizeof( QueueHeader ) + sizeof( QueueMessageColor ),    // literal
    sizeof( QueueHeader ) + sizeof( QueueMessage ),         // literal, callstack
    sizeof( QueueHeader ) + sizeof( QueueMessageColor ),    // literal, callstack
    sizeof( QueueHeader ) + sizeof( QueueGpuNewContext ),
    sizeof( QueueHeader ) + sizeof( QueueCallstackFrameSize ),
    sizeof( QueueHeader ) + sizeof( QueueCallstackFrame ),
    sizeof( QueueHeader ) + sizeof( QueueSymbolInformation ),
    sizeof( QueueHeader ) + sizeof( QueueCodeInformation ),
    sizeof( QueueHeader ) + sizeof( QueueSysTime ),
    sizeof( QueueHeader ) + sizeof( QueueTidToPid ),
    sizeof( QueueHeader ) + sizeof( QueuePlotConfig ),
    sizeof( QueueHeader ) + sizeof( QueueParamSetup ),
    sizeof( QueueHeader ),                                  // param pingback
    sizeof( QueueHeader ) + sizeof( QueueCpuTopology ),
    // keep all QueueStringTransfer below
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // string data
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // thread name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // custom string data
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // plot name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // allocated source location payload
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // callstack payload
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // callstack alloc payload
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // frame name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // frame image data
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // external name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // external thread name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // symbol code
};

static_assert( QueueItemSize == 32, "Queue item size not 32 bytes" );
static_assert( sizeof( QueueDataSize ) / sizeof( size_t ) == (uint8_t)QueueType::NUM_TYPES, "QueueDataSize mismatch" );
static_assert( sizeof( void* ) <= sizeof( uint64_t ), "Pointer size > 8 bytes" );
static_assert( sizeof( void* ) == sizeof( uintptr_t ), "Pointer size != uintptr_t" );

}

#endif
