#ifndef __TRACYEVENT_HPP__
#define __TRACYEVENT_HPP__

#include <assert.h>
#include <limits>
#include <stdint.h>
#include <string>
#include <string.h>

#include "TracyCharUtil.hpp"
#include "TracyShortPtr.hpp"
#include "TracySortedVector.hpp"
#include "TracyVector.hpp"
#include "tracy_robin_hood.h"
#include "../common/TracyForceInline.hpp"
#include "../common/TracyQueue.hpp"

namespace tracy
{

#pragma pack( 1 )

struct StringRef
{
    enum Type { Ptr, Idx };

    tracy_force_inline StringRef() : str( 0 ), __data( 0 ) {}
    tracy_force_inline StringRef( Type t, uint64_t data )
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

struct StringRefHasher
{
    size_t operator()( const StringRef& key ) const
    {
        return charutil::hash( (const char*)&key, sizeof( StringRef ) );
    }
};

struct StringRefComparator
{
    bool operator()( const StringRef& lhs, const StringRef& rhs ) const
    {
        return memcmp( &lhs, &rhs, sizeof( StringRef ) ) == 0;
    }
};

class StringIdx
{
public:
    tracy_force_inline StringIdx() { memset( m_idx, 0, sizeof( m_idx ) ); }
    tracy_force_inline StringIdx( uint32_t idx )
    {
        SetIdx( idx );
    }

    tracy_force_inline void SetIdx( uint32_t idx )
    {
        idx++;
        memcpy( m_idx, &idx, 3 );
    }

    tracy_force_inline uint32_t Idx() const
    {
        uint32_t idx = 0;
        memcpy( &idx, m_idx, 3 );
        assert( idx != 0 );
        return idx - 1;
    }

    tracy_force_inline bool Active() const
    {
        uint32_t zero = 0;
        return memcmp( m_idx, &zero, 3 ) != 0;
    }

private:
    uint8_t m_idx[3];
};

struct StringIdxHasher
{
    size_t operator()( const StringIdx& key ) const
    {
        return charutil::hash( (const char*)&key, sizeof( StringIdx ) );
    }
};

struct StringIdxComparator
{
    bool operator()( const StringIdx& lhs, const StringIdx& rhs ) const
    {
        return memcmp( &lhs, &rhs, sizeof( StringIdx ) ) == 0;
    }
};

class Int24
{
public:
    tracy_force_inline Int24() { memset( m_val, 0, sizeof( m_val ) ); }
    tracy_force_inline Int24( uint32_t val )
    {
        SetVal( val );
    }

    tracy_force_inline void SetVal( uint32_t val )
    {
        memcpy( m_val, &val, 2 );
        val >>= 16;
        memcpy( m_val+2, &val, 1 );
    }

    tracy_force_inline uint32_t Val() const
    {
        uint8_t hi;
        memcpy( &hi, m_val+2, 1 );
        uint16_t lo;
        memcpy( &lo, m_val, 2 );
        return ( uint32_t( hi ) << 16 ) | lo;
    }

private:
    uint8_t m_val[3];
};

class Int48
{
public:
    tracy_force_inline Int48() {}
    tracy_force_inline Int48( int64_t val )
    {
        SetVal( val );
    }

    tracy_force_inline void Clear()
    {
        memset( m_val, 0, 6 );
    }

    tracy_force_inline void SetVal( int64_t val )
    {
        memcpy( m_val, &val, 4 );
        val >>= 32;
        memcpy( m_val+4, &val, 2 );
    }

    tracy_force_inline int64_t Val() const
    {
        int16_t hi;
        memcpy( &hi, m_val+4, 2 );
        uint32_t lo;
        memcpy( &lo, m_val, 4 );
        return ( int64_t( uint64_t( hi ) << 32 ) ) | lo;
    }

    tracy_force_inline bool IsNonNegative() const
    {
        return ( m_val[5] >> 7 ) == 0;
    }

private:
    uint8_t m_val[6];
};

struct Int48Sort { bool operator()( const Int48& lhs, const Int48& rhs ) { return lhs.Val() < rhs.Val(); }; };


struct SourceLocationBase
{
    StringRef name;
    StringRef function;
    StringRef file;
    uint32_t line;
    uint32_t color;
};

struct SourceLocation : public SourceLocationBase
{
    mutable uint32_t namehash;
};

enum { SourceLocationSize = sizeof( SourceLocation ) };


struct ZoneEvent
{
    tracy_force_inline ZoneEvent() {};

    tracy_force_inline int64_t Start() const { return int64_t( _start_srcloc ) >> 16; }
    tracy_force_inline void SetStart( int64_t start ) { assert( start < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_start_srcloc)+2, &start, 4 ); memcpy( ((char*)&_start_srcloc)+6, ((char*)&start)+4, 2 ); }
    tracy_force_inline int64_t End() const { return int64_t( _end_child1 ) >> 16; }
    tracy_force_inline void SetEnd( int64_t end ) { assert( end < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_end_child1)+2, &end, 4 ); memcpy( ((char*)&_end_child1)+6, ((char*)&end)+4, 2 ); }
    tracy_force_inline bool IsEndValid() const { return ( _end_child1 >> 63 ) == 0; }
    tracy_force_inline int16_t SrcLoc() const { return int16_t( _start_srcloc & 0xFFFF ); }
    tracy_force_inline void SetSrcLoc( int16_t srcloc ) { memcpy( &_start_srcloc, &srcloc, 2 ); }
    tracy_force_inline int32_t Child() const { int32_t child; memcpy( &child, &_child2, 4 ); return child; }
    tracy_force_inline void SetChild( int32_t child ) { memcpy( &_child2, &child, 4 ); }
    tracy_force_inline bool HasChildren() const { uint8_t tmp; memcpy( &tmp, ((char*)&_end_child1)+1, 1 ); return ( tmp >> 7 ) == 0; }

    tracy_force_inline void SetStartSrcLoc( int64_t start, int16_t srcloc ) { assert( start < (int64_t)( 1ull << 47 ) ); start <<= 16; start |= uint16_t( srcloc ); memcpy( &_start_srcloc, &start, 8 ); }

    uint64_t _start_srcloc;
    uint16_t _child2;
    uint64_t _end_child1;
    uint32_t extra;
};

enum { ZoneEventSize = sizeof( ZoneEvent ) };
static_assert( std::is_standard_layout<ZoneEvent>::value, "ZoneEvent is not standard layout" );


struct ZoneExtra
{
    Int24 callstack;
    StringIdx text;
    StringIdx name;
    Int24 color;
};

enum { ZoneExtraSize = sizeof( ZoneExtra ) };


// This union exploits the fact that the current implementations of x64 and arm64 do not provide
// full 64 bit address space. The high bits must be bit-extended, so 0x80... is an invalid pointer.
// This allows using the highest bit as a selector between a native pointer and a table index here.
union CallstackFrameId
{
    struct
    {
        uint64_t idx : 62;
        uint64_t sel : 1;
        uint64_t custom : 1;
    };
    uint64_t data;
};

enum { CallstackFrameIdSize = sizeof( CallstackFrameId ) };

static tracy_force_inline bool operator==( const CallstackFrameId& lhs, const CallstackFrameId& rhs ) { return lhs.data == rhs.data; }


struct SampleData
{
    Int48 time;
    Int24 callstack;
};

enum { SampleDataSize = sizeof( SampleData ) };


struct SampleDataRange
{
    Int48 time;
    CallstackFrameId ip;
};

enum { SampleDataRangeSize = sizeof( SampleDataRange ) };


struct HwSampleData
{
    SortedVector<Int48, Int48Sort> cycles;
    SortedVector<Int48, Int48Sort> retired;
    SortedVector<Int48, Int48Sort> cacheRef;
    SortedVector<Int48, Int48Sort> cacheMiss;
    SortedVector<Int48, Int48Sort> branchRetired;
    SortedVector<Int48, Int48Sort> branchMiss;

    bool is_sorted() const
    {
        return
            cycles.is_sorted() &&
            retired.is_sorted() &&
            cacheRef.is_sorted() &&
            cacheMiss.is_sorted() &&
            branchRetired.is_sorted() &&
            branchMiss.is_sorted();
    }

    void sort()
    {
        if( !cycles.is_sorted() ) cycles.sort();
        if( !retired.is_sorted() ) retired.sort();
        if( !cacheRef.is_sorted() ) cacheRef.sort();
        if( !cacheMiss.is_sorted() ) cacheMiss.sort();
        if( !branchRetired.is_sorted() ) branchRetired.sort();
        if( !branchMiss.is_sorted() ) branchMiss.sort();
    }
};

enum { HwSampleDataSize = sizeof( HwSampleData ) };


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

    tracy_force_inline int64_t Time() const { return int64_t( _time_srcloc ) >> 16; }
    tracy_force_inline void SetTime( int64_t time ) { assert( time < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_time_srcloc)+2, &time, 4 ); memcpy( ((char*)&_time_srcloc)+6, ((char*)&time)+4, 2 ); }
    tracy_force_inline int16_t SrcLoc() const { return int16_t( _time_srcloc & 0xFFFF ); }
    tracy_force_inline void SetSrcLoc( int16_t srcloc ) { memcpy( &_time_srcloc, &srcloc, 2 ); }

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
    short_ptr<LockEvent> ptr;
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
    tracy_force_inline int64_t CpuStart() const { return int64_t( _cpuStart_srcloc ) >> 16; }
    tracy_force_inline void SetCpuStart( int64_t cpuStart ) { assert( cpuStart < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_cpuStart_srcloc)+2, &cpuStart, 4 ); memcpy( ((char*)&_cpuStart_srcloc)+6, ((char*)&cpuStart)+4, 2 ); }
    tracy_force_inline int64_t CpuEnd() const { return int64_t( _cpuEnd_thread ) >> 16; }
    tracy_force_inline void SetCpuEnd( int64_t cpuEnd ) { assert( cpuEnd < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_cpuEnd_thread)+2, &cpuEnd, 4 ); memcpy( ((char*)&_cpuEnd_thread)+6, ((char*)&cpuEnd)+4, 2 ); }
    tracy_force_inline int64_t GpuStart() const { return int64_t( _gpuStart_child1 ) >> 16; }
    tracy_force_inline void SetGpuStart( int64_t gpuStart ) { /*assert( gpuStart < (int64_t)( 1ull << 47 ) );*/ memcpy( ((char*)&_gpuStart_child1)+2, &gpuStart, 4 ); memcpy( ((char*)&_gpuStart_child1)+6, ((char*)&gpuStart)+4, 2 ); }
    tracy_force_inline int64_t GpuEnd() const { return int64_t( _gpuEnd_child2 ) >> 16; }
    tracy_force_inline void SetGpuEnd( int64_t gpuEnd ) { assert( gpuEnd < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_gpuEnd_child2)+2, &gpuEnd, 4 ); memcpy( ((char*)&_gpuEnd_child2)+6, ((char*)&gpuEnd)+4, 2 ); }
    tracy_force_inline int16_t SrcLoc() const { return int16_t( _cpuStart_srcloc & 0xFFFF ); }
    tracy_force_inline void SetSrcLoc( int16_t srcloc ) { memcpy( &_cpuStart_srcloc, &srcloc, 2 ); }
    tracy_force_inline uint16_t Thread() const { return uint16_t( _cpuEnd_thread & 0xFFFF ); }
    tracy_force_inline void SetThread( uint16_t thread ) { memcpy( &_cpuEnd_thread, &thread, 2 ); }
    tracy_force_inline int32_t Child() const { return int32_t( uint32_t( _gpuStart_child1 & 0xFFFF ) | ( uint32_t( _gpuEnd_child2 & 0xFFFF ) << 16 ) ); }
    tracy_force_inline void SetChild( int32_t child ) { memcpy( &_gpuStart_child1, &child, 2 ); memcpy( &_gpuEnd_child2, ((char*)&child)+2, 2 ); }

    uint64_t _cpuStart_srcloc;
    uint64_t _cpuEnd_thread;
    uint64_t _gpuStart_child1;
    uint64_t _gpuEnd_child2;
    Int24 callstack;
};

enum { GpuEventSize = sizeof( GpuEvent ) };
static_assert( std::is_standard_layout<GpuEvent>::value, "GpuEvent is not standard layout" );


struct MemEvent
{
    tracy_force_inline uint64_t Ptr() const { return uint64_t( int64_t( _ptr_csalloc1 ) >> 8 ); }
    tracy_force_inline void SetPtr( uint64_t ptr ) { memcpy( ((char*)&_ptr_csalloc1)+1, &ptr, 4 ); memcpy( ((char*)&_ptr_csalloc1)+5, ((char*)&ptr)+4, 2 ); memcpy( ((char*)&_ptr_csalloc1)+7, ((char*)&ptr)+6, 1 ); }
    tracy_force_inline uint64_t Size() const { return _size_csalloc2 >> 16; }
    tracy_force_inline void SetSize( uint64_t size ) { assert( size < ( 1ull << 47 ) ); memcpy( ((char*)&_size_csalloc2)+2, &size, 4 ); memcpy( ((char*)&_size_csalloc2)+6, ((char*)&size)+4, 2 ); }
    tracy_force_inline uint32_t CsAlloc() const { return uint8_t( _ptr_csalloc1 ) | ( uint16_t( _size_csalloc2 ) << 8 ); }
    tracy_force_inline void SetCsAlloc( uint32_t csAlloc ) { memcpy( &_ptr_csalloc1, &csAlloc, 1 ); memcpy( &_size_csalloc2, ((char*)&csAlloc)+1, 2 ); }
    tracy_force_inline int64_t TimeAlloc() const { return int64_t( _time_thread_alloc ) >> 16; }
    tracy_force_inline void SetTimeAlloc( int64_t time ) { assert( time < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_time_thread_alloc)+2, &time, 4 ); memcpy( ((char*)&_time_thread_alloc)+6, ((char*)&time)+4, 2 ); }
    tracy_force_inline int64_t TimeFree() const { return int64_t( _time_thread_free ) >> 16; }
    tracy_force_inline void SetTimeFree( int64_t time ) { assert( time < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_time_thread_free)+2, &time, 4 ); memcpy( ((char*)&_time_thread_free)+6, ((char*)&time)+4, 2 ); }
    tracy_force_inline uint16_t ThreadAlloc() const { return uint16_t( _time_thread_alloc ); }
    tracy_force_inline void SetThreadAlloc( uint16_t thread ) { memcpy( &_time_thread_alloc, &thread, 2 ); }
    tracy_force_inline uint16_t ThreadFree() const { return uint16_t( _time_thread_free ); }
    tracy_force_inline void SetThreadFree( uint16_t thread ) { memcpy( &_time_thread_free, &thread, 2 ); }

    tracy_force_inline void SetTimeThreadAlloc( int64_t time, uint16_t thread ) { time <<= 16; time |= thread; memcpy( &_time_thread_alloc, &time, 8 ); }
    tracy_force_inline void SetTimeThreadFree( int64_t time, uint16_t thread ) { uint64_t t; memcpy( &t, &time, 8 ); t <<= 16; t |= thread; memcpy( &_time_thread_free, &t, 8 ); }

    uint64_t _ptr_csalloc1;
    uint64_t _size_csalloc2;
    Int24 csFree;
    uint64_t _time_thread_alloc;
    uint64_t _time_thread_free;
};

enum { MemEventSize = sizeof( MemEvent ) };
static_assert( std::is_standard_layout<MemEvent>::value, "MemEvent is not standard layout" );


struct CallstackFrameBasic
{
    StringIdx name;
    StringIdx file;
    uint32_t line;
};

struct CallstackFrame : public CallstackFrameBasic
{
    uint64_t symAddr;
};

struct SymbolData : public CallstackFrameBasic
{
    StringIdx imageName;
    StringIdx callFile;
    uint32_t callLine;
    uint8_t isInline;
    Int24 size;
};

enum { CallstackFrameBasicSize = sizeof( CallstackFrameBasic ) };
enum { CallstackFrameSize = sizeof( CallstackFrame ) };
enum { SymbolDataSize = sizeof( SymbolData ) };


struct SymbolLocation
{
    uint64_t addr;
    uint32_t len;
};

enum { SymbolLocationSize = sizeof( SymbolLocation ) };


struct CallstackFrameData
{
    short_ptr<CallstackFrame> data;
    uint8_t size;
    StringIdx imageName;
};

enum { CallstackFrameDataSize = sizeof( CallstackFrameData ) };


struct CallstackFrameTree
{
    CallstackFrameTree( CallstackFrameId id ) : frame( id ), alloc( 0 ), count( 0 ) {}

    CallstackFrameId frame;
    uint64_t alloc;
    uint32_t count;
    unordered_flat_map<uint64_t, CallstackFrameTree> children;
    unordered_flat_set<uint32_t> callstacks;
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

    tracy_force_inline int64_t Start() const { return int64_t( _start_cpu ) >> 16; }
    tracy_force_inline void SetStart( int64_t start ) { assert( start < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_start_cpu)+2, &start, 4 ); memcpy( ((char*)&_start_cpu)+6, ((char*)&start)+4, 2 ); }
    tracy_force_inline int64_t End() const { return int64_t( _end_reason_state ) >> 16; }
    tracy_force_inline void SetEnd( int64_t end ) { assert( end < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_end_reason_state)+2, &end, 4 ); memcpy( ((char*)&_end_reason_state)+6, ((char*)&end)+4, 2 ); }
    tracy_force_inline bool IsEndValid() const { return ( _end_reason_state >> 63 ) == 0; }
    tracy_force_inline uint8_t Cpu() const { return uint8_t( _start_cpu & 0xFF ); }
    tracy_force_inline void SetCpu( uint8_t cpu ) { memcpy( &_start_cpu, &cpu, 1 ); }
    tracy_force_inline int8_t Reason() const { return int8_t( (_end_reason_state >> 8) & 0xFF ); }
    tracy_force_inline void SetReason( int8_t reason ) { memcpy( ((char*)&_end_reason_state)+1, &reason, 1 ); }
    tracy_force_inline int8_t State() const { return int8_t( _end_reason_state & 0xFF ); }
    tracy_force_inline void SetState( int8_t state ) { memcpy( &_end_reason_state, &state, 1 ); }
    tracy_force_inline int64_t WakeupVal() const { return _wakeup.Val(); }
    tracy_force_inline void SetWakeup( int64_t wakeup ) { assert( wakeup < (int64_t)( 1ull << 47 ) ); _wakeup.SetVal( wakeup ); }

    tracy_force_inline void SetStartCpu( int64_t start, uint8_t cpu ) { assert( start < (int64_t)( 1ull << 47 ) ); _start_cpu = ( uint64_t( start ) << 16 ) | cpu; }
    tracy_force_inline void SetEndReasonState( int64_t end, int8_t reason, int8_t state ) { assert( end < (int64_t)( 1ull << 47 ) ); _end_reason_state = ( uint64_t( end ) << 16 ) | ( uint64_t( reason ) << 8 ) | uint8_t( state ); }

    uint64_t _start_cpu;
    uint64_t _end_reason_state;
    Int48 _wakeup;
};

enum { ContextSwitchDataSize = sizeof( ContextSwitchData ) };


struct ContextSwitchCpu
{
    tracy_force_inline int64_t Start() const { return int64_t( _start_thread ) >> 16; }
    tracy_force_inline void SetStart( int64_t start ) { assert( start < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_start_thread)+2, &start, 4 ); memcpy( ((char*)&_start_thread)+6, ((char*)&start)+4, 2 ); }
    tracy_force_inline int64_t End() const { int64_t v; memcpy( &v, ((char*)&_end)-2, 8 ); return v >> 16; }
    tracy_force_inline void SetEnd( int64_t end ) { assert( end < (int64_t)( 1ull << 47 ) ); _end.SetVal( end ); }
    tracy_force_inline bool IsEndValid() const { return _end.IsNonNegative(); }
    tracy_force_inline uint16_t Thread() const { return uint16_t( _start_thread ); }
    tracy_force_inline void SetThread( uint16_t thread ) { memcpy( &_start_thread, &thread, 2 ); }

    tracy_force_inline void SetStartThread( int64_t start, uint16_t thread ) { assert( start < (int64_t)( 1ull << 47 ) ); _start_thread = ( uint64_t( start ) << 16 ) | thread; }

    uint64_t _start_thread;
    Int48 _end;
};

enum { ContextSwitchCpuSize = sizeof( ContextSwitchCpu ) };


struct ContextSwitchUsage
{
    ContextSwitchUsage() {}
    ContextSwitchUsage( int64_t time, uint8_t other, uint8_t own ) { SetTime( time ); SetOther( other ); SetOwn( own ); }

    tracy_force_inline int64_t Time() const { return int64_t( _time_other_own ) >> 16; }
    tracy_force_inline void SetTime( int64_t time ) { assert( time < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_time_other_own)+2, &time, 4 ); memcpy( ((char*)&_time_other_own)+6, ((char*)&time)+4, 2 ); }
    tracy_force_inline uint8_t Other() const { return uint8_t( _time_other_own ); }
    tracy_force_inline void SetOther( uint8_t other ) { memcpy( &_time_other_own, &other, 1 ); }
    tracy_force_inline uint8_t Own() const { uint8_t v; memcpy( &v, ((char*)&_time_other_own)+1, 1 );return v; }
    tracy_force_inline void SetOwn( uint8_t own ) { memcpy( ((char*)&_time_other_own)+1, &own, 1 ); }

    uint64_t _time_other_own;
};

enum { ContextSwitchUsageSize = sizeof( ContextSwitchUsage ) };


struct MessageData
{
    int64_t time;
    StringRef ref;
    uint16_t thread;
    uint32_t color;
    Int24 callstack;
};

enum { MessageDataSize = sizeof( MessageData ) };


struct PlotItem
{
    Int48 time;
    double val;
};

enum { PlotItemSize = sizeof( PlotItem ) };


struct FrameEvent
{
    int64_t start;
    int64_t end;
    int32_t frameImage;
};

enum { FrameEventSize = sizeof( FrameEvent ) };


struct FrameImage
{
    short_ptr<const char> ptr;
    uint32_t csz;
    uint16_t w, h;
    uint32_t frameRef;
    uint8_t flip;
};

enum { FrameImageSize = sizeof( FrameImage ) };


struct GhostZone
{
    Int48 start, end;
    Int24 frame;
    int32_t child;
};

enum { GhostZoneSize = sizeof( GhostZone ) };

#pragma pack()


using SrcLocCountMap = unordered_flat_map<int16_t, size_t>;

static tracy_force_inline void IncSrcLocCount( SrcLocCountMap& countMap, int16_t srcloc )
{
    const auto it = countMap.find( srcloc );
    if( it == countMap.end() )
    {
        countMap.emplace( srcloc, 1 );
        return;
    }

    assert( it->second != 0 );
    it->second++;
}

static tracy_force_inline bool DecSrcLocCount( SrcLocCountMap& countMap, int16_t srcloc )
{
    const auto it = countMap.find( srcloc );
    assert( it != countMap.end() );
    assert( it->second != 0 );

    if( it->second == 1 )
    {
        countMap.erase( it );
        return false;
    }

    it->second--;
    return true;
}

static tracy_force_inline bool HasSrcLocCount( const SrcLocCountMap& countMap, int16_t srcloc )
{
    const auto it = countMap.find( srcloc );

    if( it != countMap.end() )
    {
        assert( it->second != 0 );
        return true;
    }

    return false;
}

struct ThreadData
{
    uint64_t id;
    uint64_t count;
    Vector<short_ptr<ZoneEvent>> timeline;
    Vector<short_ptr<ZoneEvent>> stack;
    SrcLocCountMap stackCount;
    Vector<short_ptr<MessageData>> messages;
    uint32_t nextZoneId;
    Vector<uint32_t> zoneIdStack;
#ifndef TRACY_NO_STATISTICS
    Vector<int64_t> childTimeStack;
    Vector<GhostZone> ghostZones;
    uint64_t ghostIdx;
#endif
    Vector<SampleData> samples;
    SampleData pendingSample;
    uint64_t kernelSampleCnt;

    tracy_force_inline void IncStackCount( int16_t srcloc ) { IncSrcLocCount( stackCount, srcloc ); }
    tracy_force_inline bool DecStackCount( int16_t srcloc ) { return DecSrcLocCount( stackCount, srcloc ); }
};

struct GpuCtxThreadData
{
    Vector<short_ptr<GpuEvent>> timeline;
    Vector<short_ptr<GpuEvent>> stack;
};

struct GpuCtxData
{
    int64_t timeDiff;
    uint64_t thread;
    uint64_t count;
    float period;
    GpuContextType type;
    bool hasPeriod;
    bool hasCalibration;
    int64_t calibratedGpuTime;
    int64_t calibratedCpuTime;
    double calibrationMod;
    int64_t lastGpuTime;
    uint64_t overflow;
    uint32_t overflowMul;
    StringIdx name;
    unordered_flat_map<uint64_t, GpuCtxThreadData> threadData;
    short_ptr<GpuEvent> query[64*1024];
};

enum { GpuCtxDataSize = sizeof( GpuCtxData ) };

enum class LockType : uint8_t;

struct LockMap
{
    struct TimeRange
    {
        int64_t start = std::numeric_limits<int64_t>::max();
        int64_t end = std::numeric_limits<int64_t>::min();
    };

    StringIdx customName;
    int16_t srcloc;
    Vector<LockEventPtr> timeline;
    unordered_flat_map<uint64_t, uint8_t> threadMap;
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

enum class PlotType : uint8_t
{
    User,
    Memory,
    SysTime
};

enum class PlotValueFormatting : uint8_t
{
    Number,
    Memory,
    Percentage
};

struct PlotData
{
    struct PlotItemSort { bool operator()( const PlotItem& lhs, const PlotItem& rhs ) { return lhs.time.Val() < rhs.time.Val(); }; };

    uint64_t name;
    double min;
    double max;
    SortedVector<PlotItem, PlotItemSort> data;
    PlotType type;
    PlotValueFormatting format;
};

struct MemData
{
    Vector<MemEvent> data;
    Vector<uint32_t> frees;
    unordered_flat_map<uint64_t, size_t> active;
    uint64_t high = std::numeric_limits<uint64_t>::min();
    uint64_t low = std::numeric_limits<uint64_t>::max();
    uint64_t usage = 0;
    PlotData* plot = nullptr;
    bool reconstruct = false;
    uint64_t name = 0;
};

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
        return charutil::hash( (const char*)ptr, sizeof( SourceLocationBase ) );
    }
};

struct SourceLocationComparator
{
    bool operator()( const SourceLocation* lhs, const SourceLocation* rhs ) const
    {
        return memcmp( lhs, rhs, sizeof( SourceLocationBase ) ) == 0;
    }
};


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


struct Parameter
{
    uint32_t idx;
    StringRef name;
    bool isBool;
    int32_t val;
};


struct SymbolStats
{
    uint32_t incl, excl;
    unordered_flat_map<uint32_t, uint32_t> parents;
};

enum { SymbolStatsSize = sizeof( SymbolStats ) };

}

#endif
