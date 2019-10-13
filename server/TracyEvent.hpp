#ifndef __TRACYEVENT_HPP__
#define __TRACYEVENT_HPP__

#include <assert.h>
#include <limits>
#include <stdint.h>
#include <string>
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

class StringIdx
{
public:
    StringIdx() { memset( m_idx, 0, sizeof( m_idx ) ); }
    StringIdx( uint32_t idx )
    {
        SetIdx( idx );
    }

    void SetIdx( uint32_t idx )
    {
        idx++;
        memcpy( m_idx, &idx, 3 );
    }

    uint32_t Idx() const
    {
        uint32_t idx = 0;
        memcpy( &idx, m_idx, 3 );
        assert( idx != 0 );
        return idx - 1;
    }

    bool Active() const
    {
        uint32_t zero = 0;
        return memcmp( m_idx, &zero, 3 ) != 0;
    }

private:
    uint8_t m_idx[3];
};

struct __StringIdxOld
{
    uint32_t idx    : 31;
    uint32_t active : 1;
};


class Int24
{
public:
    Int24() { memset( m_val, 0, sizeof( m_val ) ); }
    Int24( uint32_t val )
    {
        SetVal( val );
    }

    void SetVal( uint32_t val )
    {
        memcpy( m_val, &val, 3 );
    }

    uint32_t Val() const
    {
        uint32_t val = 0;
        memcpy( &val, m_val, 3 );
        return val;
    }

private:
    uint8_t m_val[3];
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
    int64_t Start() const { return int64_t( _start_srcloc ) >> 16; }
    void SetStart( int64_t start ) { assert( start < (int64_t)( 1ull << 47 ) ); _start_srcloc = ( _start_srcloc & 0xFFFF ) | ( uint64_t( start ) << 16 ); }
    int64_t End() const { return int64_t( _end_child1 ) >> 16; }
    void SetEnd( int64_t end ) { assert( end < (int64_t)( 1ull << 47 ) ); _end_child1 = ( _end_child1 & 0xFFFF ) | ( uint64_t( end ) << 16 ); }
    int16_t SrcLoc() const { return int16_t( _start_srcloc & 0xFFFF ); }
    void SetSrcLoc( int16_t srcloc ) { _start_srcloc = ( _start_srcloc & 0xFFFFFFFFFFFF0000 ) | uint16_t( srcloc ); }
    int32_t Child() const { return int32_t( uint32_t( _end_child1 & 0xFFFF ) | ( uint32_t( _child2 ) << 16 ) ); }
    void SetChild( int32_t child ) { _end_child1 = ( _end_child1 & 0xFFFFFFFFFFFF0000 ) | uint16_t( child ); _child2 = uint32_t( child ) >> 16; }

    uint64_t _start_srcloc;
    uint64_t _end_child1;
    StringIdx text;
    Int24 callstack;
    StringIdx name;
    uint16_t _child2;
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

    int64_t Time() const { return int64_t( _time_srcloc ) >> 16; }
    void SetTime( int64_t time ) { assert( time < (int64_t)( 1ull << 47 ) ); _time_srcloc = ( _time_srcloc & 0xFFFF ) | ( uint64_t( time ) << 16 ); }
    int16_t SrcLoc() const { return int16_t( _time_srcloc & 0xFFFF ); }
    void SetSrcLoc( int16_t srcloc ) { _time_srcloc = ( _time_srcloc & 0xFFFFFFFFFFFF0000 ) | uint16_t( srcloc ); }

    uint64_t _time_srcloc;
    uint8_t thread;
    Type type;
};

struct LockEventShared : public LockEvent
{
    uint64_t waitShared;
    uint64_t sharedList;
};

struct LockEventPtr
{
    LockEvent* ptr;
    uint8_t lockingThread;
    uint8_t lockCount;
    uint64_t waitList;
};

enum { LockEventSize = sizeof( LockEvent ) };
enum { LockEventSharedSize = sizeof( LockEventShared ) };
enum { LockEventPtrSize = sizeof( LockEventPtr ) };

enum { MaxLockThreads = sizeof( LockEventPtr::waitList ) * 8 };
static_assert( std::numeric_limits<decltype(LockEventPtr::lockCount)>::max() >= MaxLockThreads, "Not enough space for lock count." );


struct GpuEvent
{
    int64_t CpuStart() const { return int64_t( _cpuStart_srcloc ) >> 16; }
    void SetCpuStart( int64_t cpuStart ) { assert( cpuStart < (int64_t)( 1ull << 47 ) ); _cpuStart_srcloc = ( _cpuStart_srcloc & 0xFFFF ) | ( uint64_t( cpuStart ) << 16 ); }
    int64_t CpuEnd() const { return int64_t( _cpuEnd_thread ) >> 16; }
    void SetCpuEnd( int64_t cpuEnd ) { assert( cpuEnd < (int64_t)( 1ull << 47 ) ); _cpuEnd_thread = ( _cpuEnd_thread & 0xFFFF ) | ( uint64_t( cpuEnd ) << 16 ); }
    int16_t SrcLoc() const { return int16_t( _cpuStart_srcloc & 0xFFFF ); }
    void SetSrcLoc( int16_t srcloc ) { _cpuStart_srcloc = ( _cpuStart_srcloc & 0xFFFFFFFFFFFF0000 ) | uint16_t( srcloc ); }
    uint16_t Thread() const { return uint16_t( _cpuEnd_thread & 0xFFFF ); }
    void SetThread( uint16_t thread ) { _cpuEnd_thread = ( _cpuEnd_thread & 0xFFFFFFFFFFFF0000 ) | thread; }

    uint64_t _cpuStart_srcloc;
    uint64_t _cpuEnd_thread;
    int64_t gpuStart;
    int64_t gpuEnd;
    Int24 callstack;
    int32_t child;
};

enum { GpuEventSize = sizeof( GpuEvent ) };
static_assert( std::is_standard_layout<GpuEvent>::value, "GpuEvent is not standard layout" );


struct MemEvent
{
    int64_t TimeAlloc() const { return int64_t( _time_thread_alloc ) >> 16; }
    void SetTimeAlloc( int64_t time ) { assert( time < (int64_t)( 1ull << 47 ) ); _time_thread_alloc = ( _time_thread_alloc & 0xFFFF ) | ( uint64_t( time ) << 16 ); }
    int64_t TimeFree() const { return int64_t( _time_thread_free ) >> 16; }
    void SetTimeFree( int64_t time ) { assert( time < (int64_t)( 1ull << 47 ) ); _time_thread_free = ( _time_thread_free & 0xFFFF ) | ( uint64_t( time ) << 16 ); }
    uint16_t ThreadAlloc() const { return uint16_t( _time_thread_alloc ); }
    void SetThreadAlloc( uint16_t thread ) { _time_thread_alloc = ( _time_thread_alloc & 0xFFFFFFFFFFFF0000 ) | thread; }
    uint16_t ThreadFree() const { return uint16_t( _time_thread_free ); }
    void SetThreadFree( uint16_t thread ) { _time_thread_free = ( _time_thread_free & 0xFFFFFFFFFFFF0000 ) | thread; }

    uint64_t ptr;
    uint64_t size;
    Int24 csAlloc;
    Int24 csFree;
    uint64_t _time_thread_alloc;
    uint64_t _time_thread_free;
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

struct CallstackFrameData
{
    CallstackFrame* data;
    uint8_t size;
};

enum { CallstackFrameDataSize = sizeof( CallstackFrameData ) };

// This union exploits the fact that the current implementations of x64 and arm64 do not provide
// full 64 bit address space. The high bits must be bit-extended, so 0x80... is an invalid pointer.
// This allows using the highest bit as a selector between a native pointer and a table index here.
union CallstackFrameId
{
    struct
    {
        uint64_t idx : 63;
        uint64_t sel : 1;
    };
    uint64_t data;
};

enum { CallstackFrameIdSize = sizeof( CallstackFrameId ) };


struct CallstackFrameTree
{
    CallstackFrameId frame;
    uint64_t alloc;
    uint32_t count;
    flat_hash_map<uint64_t, CallstackFrameTree, nohash<uint64_t>> children;
    flat_hash_set<uint32_t, nohash<uint32_t>> callstacks;
};

enum { CallstackFrameTreeSize = sizeof( CallstackFrameTree ) };


struct CrashEvent
{
    uint64_t thread = 0;
    int64_t time = 0;
    uint64_t message = 0;
    uint32_t callstack = 0;
};

enum { CrashEventSize = sizeof( CrashEvent ) };


struct ContextSwitchData
{
    enum : int8_t { NoState = 100 };
    enum : int8_t { Wakeup = -2 };

    int64_t Start() const { return int64_t( _start_cpu ) >> 8; }
    void SetStart( int64_t start ) { assert( start < (int64_t)( 1ull << 47 ) ); _start_cpu = ( _start_cpu & 0xFF ) | ( uint64_t( start ) << 8 ); }
    int64_t End() const { return int64_t( _end_reason_state ) >> 16; }
    void SetEnd( int64_t end ) { assert( end < (int64_t)( 1ull << 47 ) ); _end_reason_state = ( _end_reason_state & 0xFFFF ) | ( uint64_t( end ) << 16 ); }
    uint8_t Cpu() const { return uint8_t( _start_cpu & 0xFF ); }
    void SetCpu( uint8_t cpu ) { _start_cpu = ( _start_cpu & 0xFFFFFFFFFFFFFF00 ) | uint8_t( cpu ); }
    int8_t Reason() const { return int8_t( (_end_reason_state >> 8) & 0xFF ); }
    void SetReason( int8_t reason ) { _end_reason_state = ( _end_reason_state & 0xFFFFFFFFFFFF00FF ) | ( uint64_t( reason ) << 8 ); }
    int8_t State() const { return int8_t( _end_reason_state & 0xFF ); }
    void SetState( int8_t state ) { _end_reason_state = ( _end_reason_state & 0xFFFFFFFFFFFFFF00 ) | uint8_t( state ); }

    uint64_t _start_cpu;
    uint64_t _end_reason_state;
    int64_t wakeup;
};

enum { ContextSwitchDataSize = sizeof( ContextSwitchData ) };


struct ContextSwitchCpu
{
    int64_t Start() const { return int64_t( _start_thread ) >> 16; }
    void SetStart( int64_t start ) { assert( start < (int64_t)( 1ull << 47 ) ); _start_thread = ( _start_thread & 0xFFFF ) | ( uint64_t( start ) << 16 ); }
    int64_t End() const { return _end; }
    void SetEnd( int64_t end ) { assert( end < (int64_t)( 1ull << 47 ) ); _end = end; }
    uint16_t Thread() const { return uint16_t( _start_thread ); }
    void SetThread( uint16_t thread ) { _start_thread = ( _start_thread & 0xFFFFFFFFFFFF0000 ) | thread; }

    uint64_t _start_thread;
    uint64_t _end;
};

enum { ContextSwitchCpuSize = sizeof( ContextSwitchCpu ) };


struct MessageData
{
    int64_t time;
    StringRef ref;
    uint16_t thread;
    uint32_t color;
};

enum { MessageDataSize = sizeof( MessageData ) };

#pragma pack()


struct ThreadData
{
    uint64_t id;
    uint64_t count;
    Vector<ZoneEvent*> timeline;
    Vector<ZoneEvent*> stack;
    Vector<MessageData*> messages;
    uint32_t nextZoneId;
    Vector<uint32_t> zoneIdStack;
};

struct GpuCtxThreadData
{
    Vector<GpuEvent*> timeline;
    Vector<GpuEvent*> stack;
};

struct GpuCtxData
{
    int64_t timeDiff;
    uint64_t thread;
    uint64_t count;
    uint8_t accuracyBits;
    float period;
    flat_hash_map<uint64_t, GpuCtxThreadData, nohash<uint64_t>> threadData;
    GpuEvent* query[64*1024];
};

struct LockMap
{
    struct TimeRange
    {
        int64_t start = std::numeric_limits<int64_t>::max();
        int64_t end = std::numeric_limits<int64_t>::min();
    };

    int16_t srcloc;
    Vector<LockEventPtr> timeline;
    flat_hash_map<uint64_t, uint8_t, nohash<uint64_t>> threadMap;
    std::vector<uint64_t> threadList;
    LockType type;
    int64_t timeAnnounce;
    int64_t timeTerminate;
    bool valid;
    bool isContended;

    TimeRange range[64];
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

enum class PlotType : uint8_t
{
    User,
    Memory,
    SysTime
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

struct FrameEvent
{
    int64_t start;
    int64_t end;
    int32_t frameImage;
};

enum { FrameEventSize = sizeof( FrameEvent ) };

struct FrameData
{
    uint64_t name;
    Vector<FrameEvent> frames;
    uint8_t continuous;

    int64_t min = std::numeric_limits<int64_t>::max();
    int64_t max = std::numeric_limits<int64_t>::min();
    int64_t total = 0;
    double sumSq = 0;
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

struct FrameImage
{
    const char* ptr;
    uint32_t csz;
    uint16_t w, h;
    uint32_t frameRef;
    uint8_t flip;
};

enum { FrameImageSize = sizeof( FrameImage ) };

struct ContextSwitch
{
    Vector<ContextSwitchData> v;
    int64_t runningTime = 0;
};

struct CpuData
{
    Vector<ContextSwitchCpu> cs;
};

struct CpuThreadData
{
    int64_t runningTime = 0;
    uint32_t runningRegions = 0;
    uint32_t migrations = 0;
};

enum { CpuThreadDataSize = sizeof( CpuThreadData ) };

}

#endif
