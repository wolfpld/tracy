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
    ZoneBeginAllocSrcLocCallstack,
    CallstackSerial,
    Callstack,
    CallstackAlloc,
    CallstackSample,
    FrameImage,
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
    MemAllocNamed,
    MemFree,
    MemFreeNamed,
    MemAllocCallstack,
    MemAllocCallstackNamed,
    MemFreeCallstack,
    MemFreeCallstackNamed,
    GpuZoneBegin,
    GpuZoneBeginCallstack,
    GpuZoneBeginAllocSrcLoc,
    GpuZoneBeginAllocSrcLocCallstack,
    GpuZoneEnd,
    GpuZoneBeginSerial,
    GpuZoneBeginCallstackSerial,
    GpuZoneBeginAllocSrcLocSerial,
    GpuZoneBeginAllocSrcLocCallstackSerial,
    GpuZoneEndSerial,
    PlotData,
    ContextSwitch,
    ThreadWakeup,
    GpuTime,
    GpuContextName,
    Terminate,
    KeepAlive,
    ThreadContext,
    GpuCalibration,
    Crash,
    CrashReport,
    ZoneValidation,
    ZoneColor,
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
    AckServerQueryNoop,
    AckSourceCodeNotAvailable,
    CpuTopology,
    SingleStringData,
    SecondStringData,
    MemNamePayload,
    StringData,
    ThreadName,
    PlotName,
    SourceLocationPayload,
    CallstackPayload,
    CallstackAllocPayload,
    FrameName,
    FrameImageData,
    ExternalName,
    ExternalThreadName,
    SymbolCode,
    SourceCode,
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

struct QueueZoneColor
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
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

struct QueueFrameImage
{
    uint32_t frame;
    uint16_t w;
    uint16_t h;
    uint8_t flip;
};

struct QueueFrameImageFat : public QueueFrameImage
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

struct QueueZoneTextFat
{
    uint64_t text;      // ptr
    uint16_t size;
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
};

struct QueueLockWait
{
    uint64_t thread;
    uint32_t id;
    int64_t time;
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
};

struct QueueLockNameFat : public QueueLockName
{
    uint64_t name;      // ptr
    uint16_t size;
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
};

struct QueueMessageColor : public QueueMessage
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

struct QueueMessageLiteral : public QueueMessage
{
    uint64_t text;      // ptr
};

struct QueueMessageColorLiteral : public QueueMessageColor
{
    uint64_t text;      // ptr
};

struct QueueMessageFat : public QueueMessage
{
    uint64_t text;      // ptr
    uint16_t size;
};

struct QueueMessageColorFat : public QueueMessageColor
{
    uint64_t text;      // ptr
    uint16_t size;
};

// Don't change order, only add new entries at the end, this is also used on trace dumps!
enum class GpuContextType : uint8_t
{
    Invalid,
    OpenGl,
    Vulkan,
    OpenCL,
    Direct3D12,
    Direct3D11
};

enum GpuContextFlags : uint8_t
{
    GpuContextCalibration   = 1 << 0
};

struct QueueGpuNewContext
{
    int64_t cpuTime;
    int64_t gpuTime;
    uint64_t thread;
    float period;
    uint8_t context;
    GpuContextFlags flags;
    GpuContextType type;
};

struct QueueGpuZoneBeginLean
{
    int64_t cpuTime;
    uint64_t thread;
    uint16_t queryId;
    uint8_t context;
};

struct QueueGpuZoneBegin : public QueueGpuZoneBeginLean
{
    uint64_t srcloc;
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

struct QueueGpuCalibration
{
    int64_t gpuTime;
    int64_t cpuTime;
    int64_t cpuDelta;
    uint8_t context;
};

struct QueueGpuContextName
{
    uint8_t context;
};

struct QueueGpuContextNameFat : public QueueGpuContextName
{
    uint64_t ptr;
    uint16_t size;
};

struct QueueMemNamePayload
{
    uint64_t name;
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

struct QueueCallstackFat
{
    uint64_t ptr;
};

struct QueueCallstackAllocFat
{
    uint64_t ptr;
    uint64_t nativePtr;
};

struct QueueCallstackSample
{
    int64_t time;
    uint64_t thread;
};

struct QueueCallstackSampleFat : public QueueCallstackSample
{
    uint64_t ptr;
};

struct QueueCallstackFrameSize
{
    uint64_t ptr;
    uint8_t size;
};

struct QueueCallstackFrame
{
    uint32_t line;
    uint64_t symAddr;
    uint32_t symLen;
};

struct QueueSymbolInformation
{
    uint32_t line;
    uint64_t symAddr;
};

struct QueueCodeInformation
{
    uint64_t ptr;
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
        QueueZoneColor zoneColor;
        QueueZoneValue zoneValue;
        QueueStringTransfer stringTransfer;
        QueueFrameMark frameMark;
        QueueFrameImage frameImage;
        QueueFrameImageFat frameImageFat;
        QueueSourceLocation srcloc;
        QueueZoneTextFat zoneTextFat;
        QueueLockAnnounce lockAnnounce;
        QueueLockTerminate lockTerminate;
        QueueLockWait lockWait;
        QueueLockObtain lockObtain;
        QueueLockRelease lockRelease;
        QueueLockMark lockMark;
        QueueLockName lockName;
        QueueLockNameFat lockNameFat;
        QueuePlotData plotData;
        QueueMessage message;
        QueueMessageColor messageColor;
        QueueMessageLiteral messageLiteral;
        QueueMessageColorLiteral messageColorLiteral;
        QueueMessageFat messageFat;
        QueueMessageColorFat messageColorFat;
        QueueGpuNewContext gpuNewContext;
        QueueGpuZoneBegin gpuZoneBegin;
        QueueGpuZoneBeginLean gpuZoneBeginLean;
        QueueGpuZoneEnd gpuZoneEnd;
        QueueGpuTime gpuTime;
        QueueGpuCalibration gpuCalibration;
        QueueGpuContextName gpuContextName;
        QueueGpuContextNameFat gpuContextNameFat;
        QueueMemAlloc memAlloc;
        QueueMemFree memFree;
        QueueMemNamePayload memName;
        QueueCallstackFat callstackFat;
        QueueCallstackAllocFat callstackAllocFat;
        QueueCallstackSample callstackSample;
        QueueCallstackSampleFat callstackSampleFat;
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
    sizeof( QueueHeader ),                                  // zone text
    sizeof( QueueHeader ),                                  // zone name
    sizeof( QueueHeader ) + sizeof( QueueMessage ),
    sizeof( QueueHeader ) + sizeof( QueueMessageColor ),
    sizeof( QueueHeader ) + sizeof( QueueMessage ),         // callstack
    sizeof( QueueHeader ) + sizeof( QueueMessageColor ),    // callstack
    sizeof( QueueHeader ) + sizeof( QueueMessage ),         // app info
    sizeof( QueueHeader ) + sizeof( QueueZoneBeginLean ),   // allocated source location
    sizeof( QueueHeader ) + sizeof( QueueZoneBeginLean ),   // allocated source location, callstack
    sizeof( QueueHeader ),                                  // callstack memory
    sizeof( QueueHeader ),                                  // callstack
    sizeof( QueueHeader ),                                  // callstack alloc
    sizeof( QueueHeader ) + sizeof( QueueCallstackSample ),
    sizeof( QueueHeader ) + sizeof( QueueFrameImage ),
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
    sizeof( QueueHeader ) + sizeof( QueueMemAlloc ),        // named
    sizeof( QueueHeader ) + sizeof( QueueMemFree ),
    sizeof( QueueHeader ) + sizeof( QueueMemFree ),         // named
    sizeof( QueueHeader ) + sizeof( QueueMemAlloc ),        // callstack
    sizeof( QueueHeader ) + sizeof( QueueMemAlloc ),        // callstack, named
    sizeof( QueueHeader ) + sizeof( QueueMemFree ),         // callstack
    sizeof( QueueHeader ) + sizeof( QueueMemFree ),         // callstack, named
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBegin ),
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBegin ),    // callstack
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBeginLean ),// allocated source location
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBeginLean ),// allocated source location, callstack
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneEnd ),
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBegin ),    // serial
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBegin ),    // serial, callstack
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBeginLean ),// serial, allocated source location
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneBeginLean ),// serial, allocated source location, callstack
    sizeof( QueueHeader ) + sizeof( QueueGpuZoneEnd ),      // serial
    sizeof( QueueHeader ) + sizeof( QueuePlotData ),
    sizeof( QueueHeader ) + sizeof( QueueContextSwitch ),
    sizeof( QueueHeader ) + sizeof( QueueThreadWakeup ),
    sizeof( QueueHeader ) + sizeof( QueueGpuTime ),
    sizeof( QueueHeader ) + sizeof( QueueGpuContextName ),
    // above items must be first
    sizeof( QueueHeader ),                                  // terminate
    sizeof( QueueHeader ),                                  // keep alive
    sizeof( QueueHeader ) + sizeof( QueueThreadContext ),
    sizeof( QueueHeader ) + sizeof( QueueGpuCalibration ),
    sizeof( QueueHeader ),                                  // crash
    sizeof( QueueHeader ) + sizeof( QueueCrashReport ),
    sizeof( QueueHeader ) + sizeof( QueueZoneValidation ),
    sizeof( QueueHeader ) + sizeof( QueueZoneColor ),
    sizeof( QueueHeader ) + sizeof( QueueZoneValue ),
    sizeof( QueueHeader ) + sizeof( QueueFrameMark ),       // continuous frames
    sizeof( QueueHeader ) + sizeof( QueueFrameMark ),       // start
    sizeof( QueueHeader ) + sizeof( QueueFrameMark ),       // end
    sizeof( QueueHeader ) + sizeof( QueueSourceLocation ),
    sizeof( QueueHeader ) + sizeof( QueueLockAnnounce ),
    sizeof( QueueHeader ) + sizeof( QueueLockTerminate ),
    sizeof( QueueHeader ) + sizeof( QueueLockMark ),
    sizeof( QueueHeader ) + sizeof( QueueMessageLiteral ),
    sizeof( QueueHeader ) + sizeof( QueueMessageColorLiteral ),
    sizeof( QueueHeader ) + sizeof( QueueMessageLiteral ),  // callstack
    sizeof( QueueHeader ) + sizeof( QueueMessageColorLiteral ), // callstack
    sizeof( QueueHeader ) + sizeof( QueueGpuNewContext ),
    sizeof( QueueHeader ) + sizeof( QueueCallstackFrameSize ),
    sizeof( QueueHeader ) + sizeof( QueueCallstackFrame ),
    sizeof( QueueHeader ) + sizeof( QueueSymbolInformation ),
    sizeof( QueueHeader ) + sizeof( QueueCodeInformation ),
    sizeof( QueueHeader ) + sizeof( QueueSysTime ),
    sizeof( QueueHeader ) + sizeof( QueueTidToPid ),
    sizeof( QueueHeader ) + sizeof( QueuePlotConfig ),
    sizeof( QueueHeader ) + sizeof( QueueParamSetup ),
    sizeof( QueueHeader ),                                  // server query acknowledgement
    sizeof( QueueHeader ),                                  // source code not available
    sizeof( QueueHeader ) + sizeof( QueueCpuTopology ),
    sizeof( QueueHeader ),                                  // single string data
    sizeof( QueueHeader ),                                  // second string data
    sizeof( QueueHeader ) + sizeof( QueueMemNamePayload ),
    // keep all QueueStringTransfer below
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // string data
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // thread name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // plot name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // allocated source location payload
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // callstack payload
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // callstack alloc payload
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // frame name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // frame image data
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // external name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // external thread name
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // symbol code
    sizeof( QueueHeader ) + sizeof( QueueStringTransfer ),  // source code
};

static_assert( QueueItemSize == 32, "Queue item size not 32 bytes" );
static_assert( sizeof( QueueDataSize ) / sizeof( size_t ) == (uint8_t)QueueType::NUM_TYPES, "QueueDataSize mismatch" );
static_assert( sizeof( void* ) <= sizeof( uint64_t ), "Pointer size > 8 bytes" );
static_assert( sizeof( void* ) == sizeof( uintptr_t ), "Pointer size != uintptr_t" );

}

#endif
