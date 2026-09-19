#ifndef __TRACYLOCKS_HPP__
#define __TRACYLOCKS_HPP__

#include <algorithm>
#include <assert.h>
#include <limits>
#include <stdint.h>
#include <string.h>

#include "TracyEvent.hpp"
#include "TracyVector.hpp"
#include "tracy_robin_hood.h"
#include "../public/common/TracyForceInline.hpp"
#include "../public/common/TracyQueue.hpp"

namespace tracy
{

#pragma pack( push, 1 )

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

    static constexpr uint32_t NoEvent = 0xFFFFFFFF;
    static constexpr uint16_t NoThread = 0xFFFF;

    tracy_force_inline int64_t Time() const { return int64_t( _time_srcloc ) >> 16; }
    tracy_force_inline void SetTime( int64_t time ) { assert( time < (int64_t)( 1ull << 47 ) ); memcpy( ((char*)&_time_srcloc)+2, &time, 4 ); memcpy( ((char*)&_time_srcloc)+6, ((char*)&time)+4, 2 ); }
    tracy_force_inline int16_t SrcLoc() const { return int16_t( _time_srcloc & 0xFFFF ); }
    tracy_force_inline void SetSrcLoc( int16_t srcloc ) { memcpy( &_time_srcloc, &srcloc, 2 ); }

    uint64_t _time_srcloc;
    uint16_t thread;
    uint8_t type;
};

namespace LockEventState
{
enum Type : uint8_t
{
    Nothing         = 1 << 0,
    HasLock         = 1 << 1,
    HasBlockingLock = 1 << 2,
    WaitLock        = 1 << 3
};
}

namespace LockEventFlags
{
enum : uint8_t
{
    Waiting       = 1 << 0,
    SharedWaiting = 1 << 1,
    SharedHolding = 1 << 2,
    LockHolding   = 1 << 3
};
}

struct LockSegment
{
    uint32_t evStart;
    uint32_t nextEv;          // event that closed it; NoEvent = open
    uint8_t state;
    uint8_t flags;            // LockEventFlags of the segment thread at evStart
};

struct LockHolderChange
{
    uint32_t idx;             // event index at which the exclusive state changed
    uint16_t holder;          // curLockingThread after the event
    uint16_t count;           // curLockCount after the event
};
#pragma pack( pop )

struct LockThreadInfo
{
    uint64_t thread;
    int64_t firstTime = std::numeric_limits<int64_t>::max();
    int64_t lastTime = std::numeric_limits<int64_t>::min();
    int64_t waitTotal = 0;    // sum of Wait/WaitShared -> Obtain/ObtainShared durations
    uint64_t waitCount = 0;   // completed wait pairs
    int64_t openWaitStart = 0;
    bool hasOpenWait = false;
    uint32_t lastWaitObtain = LockEvent::NoEvent;
    uint8_t flags = 0;
    uint8_t curState = LockEventState::Nothing;
    bool inPending = false;   // membership of LockMap::pendingStarts
    Vector<LockSegment> segments;    // sorted by evStart; at most one open (last)
    Vector<uint32_t> marks;          // own srcloc != 0 event indices, ascending
    Vector<uint32_t> yellowSegs;     // indices into segments, ascending; segment states are final at creation, so appends keep this searchable
    Vector<uint32_t> redSegs;
};

struct LockMap
{
    StringIdx customName;
    int16_t srcloc;
    LockType type;
    int64_t timeAnnounce;
    int64_t timeTerminate;
    bool valid;
    bool isContended;
    bool legacyInversions = false;  // traces from clients predating the release-ordering fix can invert handoffs; see SegmentPass

    Vector<LockEvent> timeline;      // append-only, sorted by time
    Vector<LockThreadInfo> threads;  // slot-indexed
    unordered_flat_map<uint64_t, uint16_t> threadMap;

    // The waiter counters always equal the respective flag's popcount over all
    // slots; decrements are flag-gated, so they cannot underflow.
    uint16_t curLockingThread = 0;
    uint16_t curLockCount = 0;
    uint16_t curWaitCount = 0, curWaitSharedCount = 0, curSharedCount = 0;
    Vector<uint16_t> pendingStarts;  // slots without an open segment whose derived state can change on an acquire or on the exclusive draining to zero: waiting flags, and shared holds recorded under an exclusive holder
    Vector<uint16_t> activeSlots;    // slots with an open segment, excluding pinned WaitLock slots (see PinnedWait)
    Vector<LockHolderChange> holderChanges;  // exclusive holder/count after each Obtain|Release, ascending idx

    int64_t holdTotal = 0, waitTotalAgg = 0;
    uint32_t maxWaiting = 0;
    int64_t openHoldStart = 0, openWaitAggStart = 0;
    bool holdOpen = false, waitAggOpen = false;

    Vector<uint16_t> passScratch;    // candidate set of the per-event segment pass

    ~LockMap()
    {
        for( auto& ti : threads )
        {
            ti.segments.~Vector();
            ti.marks.~Vector();
            ti.yellowSegs.~Vector();
            ti.redSegs.~Vector();
        }
    }
};

void InitLockMap( LockMap& map, int16_t srcloc, LockType type, int64_t announce );
void ReserveLockSlots( LockMap& map, const uint64_t* threadIds, size_t count );
uint16_t GetLockSlot( LockMap& map, uint64_t thread );
void AppendLockEvent( LockMap& map, int64_t time, uint16_t slot, LockEvent::Type type, int16_t srcloc = 0 );
bool ApplyLockMark( LockMap& map, uint16_t slot, int16_t srcloc );
LockEventState::Type ResolveLockState( const LockMap& map, uint16_t slot );

struct LockHolderInfo
{
    uint16_t holder;
    uint16_t count;
};
tracy_force_inline LockHolderInfo HolderAt( const LockMap& map, uint32_t at )
{
    const auto& lc = map.holderChanges;
    auto it = std::upper_bound( lc.begin(), lc.end(), at, []( uint32_t v, const LockHolderChange& e ) { return v < e.idx; } );
    if( it == lc.begin() ) return { 0, 0 };
    --it;
    return { it->holder, it->count };
}

}

#endif
