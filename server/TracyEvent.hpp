#ifndef __TRACYEVENT_HPP__
#define __TRACYEVENT_HPP__

#include <limits>
#include <string.h>

#include "TracyCharUtil.hpp"
#include "TracyVector.hpp"
#include "tracy_flat_hash_map.hpp"

namespace tracy
{

#pragma pack( 1 )

struct StringRef
{
    enum Type { Ptr, Idx };

    StringRef() : str( 0 ), __data( 0 ) {}
    StringRef( Type t, uint64_t data )
        : str( data )
        , __data( 0 )
    {
        isidx = t == Idx;
        active = 1;
    }

    uint64_t str;

    union
    {
        struct
        {
            uint8_t isidx   : 1;
            uint8_t active  : 1;
        };
        uint8_t __data;
    };
};

struct StringIdx
{
    StringIdx() : __data( 0 ) {}
    StringIdx( uint32_t _idx )
        : __data( 0 )
    {
        idx = _idx;
        active = 1;
    }

    union
    {
        struct
        {
            uint32_t idx    : 31;
            uint32_t active : 1;
        };
        uint32_t __data;
    };
};

struct SourceLocation
{
    StringRef name;
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
    StringIdx text;
    uint32_t callstack;
    StringIdx name;

    // This must be last. All above is read/saved as-is.
    Vector<ZoneEvent*> child;
};

enum { ZoneEventSize = sizeof( ZoneEvent ) };
static_assert( std::is_standard_layout<ZoneEvent>::value, "ZoneEvent is not standard layout" );

struct LockEvent
{
    enum class Type : uint8_t
    {
        Wait,
        Obtain,
        Release,
        WaitShared,
        ObtainShared,
        ReleaseShared
    };

    int64_t time;
    int32_t srcloc;
    uint8_t thread;
    Type type;
    // All above is read/saved as-is.

    uint8_t lockingThread;
    uint8_t lockCount;
    uint64_t waitList;
};

struct LockEventShared : public LockEvent
{
    uint64_t waitShared;
    uint64_t sharedList;
};

enum { LockEventSize = sizeof( LockEvent ) };
enum { LockEventSharedSize = sizeof( LockEventShared ) };

enum { MaxLockThreads = sizeof( LockEvent::waitList ) * 8 };
static_assert( std::numeric_limits<decltype(LockEvent::lockCount)>::max() >= MaxLockThreads, "Not enough space for lock count." );


struct GpuEvent
{
    int64_t cpuStart;
    int64_t cpuEnd;
    int64_t gpuStart;
    int64_t gpuEnd;
    int32_t srcloc;
    int32_t callstack;
    // All above is read/saved as-is.

    uint16_t thread;
    Vector<GpuEvent*> child;
};

enum { GpuEventSize = sizeof( GpuEvent ) };
static_assert( std::is_standard_layout<GpuEvent>::value, "GpuEvent is not standard layout" );


struct MemEvent
{
    uint64_t ptr;
    uint64_t size;
    int64_t timeAlloc;
    int64_t timeFree;
    uint32_t csAlloc;
    uint32_t csFree;
    // All above is read/saved as-is.

    uint16_t threadAlloc;
    uint16_t threadFree;
};

enum { MemEventSize = sizeof( MemEvent ) };
static_assert( std::is_standard_layout<MemEvent>::value, "MemEvent is not standard layout" );


struct CallstackFrame
{
    StringIdx name;
    StringIdx file;
    uint32_t line;
};

enum { CallstackFrameSize = sizeof( CallstackFrame ) };

#pragma pack()


struct MessageData
{
    int64_t time;
    StringRef ref;
    uint64_t thread;
};

struct ThreadData
{
    uint64_t id;
    uint64_t count;
    Vector<ZoneEvent*> timeline;
    Vector<ZoneEvent*> stack;
    Vector<MessageData*> messages;
};

struct GpuCtxData
{
    int64_t timeDiff;
    uint64_t thread;
    uint64_t count;
    Vector<GpuEvent*> timeline;
    Vector<GpuEvent*> stack;
    uint8_t accuracyBits;
    float period;
    GpuEvent* query[64*1024];
};

struct LockMap
{
    uint32_t srcloc;
    Vector<LockEvent*> timeline;
    flat_hash_map<uint64_t, uint8_t, nohash<uint64_t>> threadMap;
    std::vector<uint64_t> threadList;
    LockType type;
    bool valid;
};

struct LockHighlight
{
    int64_t id;
    int64_t begin;
    int64_t end;
    uint8_t thread;
    bool blocked;
};

struct PlotItem
{
    int64_t time;
    double val;
};

enum class PlotType
{
    User,
    Memory
};

struct PlotData
{
    uint64_t name;
    double min;
    double max;
    Vector<PlotItem> data;
    Vector<PlotItem> postpone;
    uint64_t postponeTime;
    PlotType type;
};

struct MemData
{
    Vector<MemEvent> data;
    Vector<uint64_t> frees;
    flat_hash_map<uint64_t, size_t, nohash<uint64_t>> active;
    uint64_t high = std::numeric_limits<uint64_t>::min();
    uint64_t low = std::numeric_limits<uint64_t>::max();
    uint64_t usage = 0;
    PlotData* plot = nullptr;
};

struct StringLocation
{
    const char* ptr;
    uint32_t idx;
};

struct SourceLocationHasher
{
    size_t operator()( const SourceLocation* ptr ) const
    {
        return charutil::hash( (const char*)ptr, sizeof( SourceLocation ) );
    }
    typedef tracy::power_of_two_hash_policy hash_policy;
};

struct SourceLocationComparator
{
    bool operator()( const SourceLocation* lhs, const SourceLocation* rhs ) const
    {
        return memcmp( lhs, rhs, sizeof( SourceLocation ) ) == 0;
    }
};

}

#endif
