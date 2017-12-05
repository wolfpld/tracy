#ifndef __TRACYEVENT_HPP__
#define __TRACYEVENT_HPP__

#include <limits>
#include <string.h>

#include "TracyVector.hpp"
#include "tracy_flat_hash_map.hpp"

namespace tracy
{

#pragma pack( 1 )

struct StringRef
{
    enum Type { Ptr, Idx };

    StringRef() : __data( 0 ) {}
    StringRef( Type t, uint64_t data )
        : isidx( t == Idx )
        , active( 1 )
    {
        if( isidx )
        {
            stridx = data;
        }
        else
        {
            strptr = data;
        }
    }

    union
    {
        uint64_t strptr;
        uint64_t stridx;
    };

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
    StringIdx( uint32_t idx )
        : idx( idx )
        , active( 1 )
    {}

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


struct GpuEvent
{
    int64_t cpuStart;
    int64_t cpuEnd;
    int64_t gpuStart;
    int64_t gpuEnd;
    int32_t srcloc;

    Vector<GpuEvent*> child;
};

enum { GpuEventSize = sizeof( GpuEvent ) };

#pragma pack()


struct MessageData
{
    int64_t time;
    StringRef ref;
};

struct ThreadData
{
    uint64_t id;
    uint64_t count;
    bool showFull;
    bool visible;
    Vector<ZoneEvent*> timeline;
    Vector<ZoneEvent*> stack;
    Vector<MessageData*> messages;
};

struct GpuCtxResync
{
    int64_t timeDiff;
    uint16_t events;
};

struct GpuCtxData
{
    int64_t timeDiff;
    uint64_t thread;
    uint64_t count;
    Vector<GpuEvent*> timeline;
    Vector<GpuEvent*> stack;
    Vector<GpuEvent*> queue;
    Vector<GpuCtxResync> resync;
    uint8_t accuracyBits;
    bool showFull;
    bool visible;
};

struct LockMap
{
    uint32_t srcloc;
    Vector<LockEvent*> timeline;
    std::unordered_map<uint64_t, uint8_t> threadMap;
    std::vector<uint64_t> threadList;
    bool visible;
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

struct PlotData
{
    uint64_t name;
    double min;
    double max;
    bool showFull;
    bool visible;
    Vector<PlotItem> data;
    Vector<PlotItem> postpone;
    uint64_t postponeTime;
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
