#include <utility>

#include "TracyLocks.hpp"

namespace tracy
{

void InitLockMap( LockMap& map, int16_t srcloc, LockType type, int64_t announce )
{
    map.srcloc = srcloc;
    map.type = type;
    map.timeAnnounce = announce;
    map.timeTerminate = 0;
    map.valid = true;
    map.isContended = false;
}

void ReserveLockSlots( LockMap& map, const uint64_t* threadIds, size_t count )
{
    const size_t base = map.threads.size();
    assert( base + count <= 0xFFFF );
    map.threadMap.reserve( base + count );
    map.threads.reserve( base + count );
    for( size_t i=0; i<count; i++ )
    {
        map.threadMap.emplace( threadIds[i], ( uint16_t )( base + i ) );
        LockThreadInfo ti;
        ti.thread = threadIds[i];
        map.threads.push_back( std::move( ti ) );
    }
}

uint16_t GetLockSlot( LockMap& map, uint64_t thread )
{
    auto it = map.threadMap.find( thread );
    if( it != map.threadMap.end() ) return it->second;
    if( map.threads.size() >= LockEvent::NoThread ) return LockEvent::NoThread;
    const auto slot = ( uint16_t )map.threads.size();
    map.threadMap.emplace( thread, slot );
    LockThreadInfo ti;
    ti.thread = thread;
    map.threads.push_back( std::move( ti ) );
    return slot;
}

static tracy_force_inline void EraseSlot( Vector<uint16_t>& vec, uint16_t slot )
{
    for( size_t i=0; i<vec.size(); i++ )
    {
        if( vec[i] == slot )
        {
            vec[i] = vec.back();
            vec.pop_back();
            return;
        }
    }
}

// a pure waiter settled at WaitLock is invariant at foreign events: its flags can only change at
// its own events (self is always visited) and drain-time flag clears reach holders
static tracy_force_inline bool PinnedWait( uint8_t state, uint8_t flags )
{
    return state == LockEventState::WaitLock && ( flags & ( LockEventFlags::Waiting | LockEventFlags::SharedWaiting ) ) != 0 &&
           ( flags & LockEventFlags::SharedHolding ) == 0;
}

static void CacheSeverity( LockThreadInfo& ti, uint32_t sidx, uint8_t state )
{
    if( state == LockEventState::HasBlockingLock ) ti.yellowSegs.push_back( sidx );
    else if( state == LockEventState::WaitLock ) ti.redSegs.push_back( sidx );
}

LockEventState::Type ResolveLockState( const LockMap& map, uint16_t slot )
{
    const auto& ti = map.threads[slot];
    const bool waiting = ( ti.flags & LockEventFlags::Waiting ) != 0;
    const bool sharedWaiting = ( ti.flags & LockEventFlags::SharedWaiting ) != 0;
    const bool sharedHolding = ( ti.flags & LockEventFlags::SharedHolding ) != 0;
    const bool holding = map.curLockCount > 0 && map.curLockingThread == slot;
    const bool exclOthers = ( map.curWaitCount - ( waiting ? 1 : 0 ) ) > 0;
    const bool sharedOthers = ( map.curWaitSharedCount - ( sharedWaiting ? 1 : 0 ) ) > 0;

    if( map.type == LockType::Lockable )
    {
        if( holding ) return exclOthers ? LockEventState::HasBlockingLock : LockEventState::HasLock;
        if( map.curLockCount > 0 && waiting ) return LockEventState::WaitLock;
        return LockEventState::Nothing;
    }
    else
    {
        if( holding ) return ( exclOthers || sharedOthers ) ? LockEventState::HasBlockingLock : LockEventState::HasLock;
        if( map.curLockCount > 0 && ( waiting || sharedWaiting ) ) return LockEventState::WaitLock;
        // a shared holder's own exclusive wait is an upgrade request - a deadlock - so the check is self-inclusive
        if( map.curLockCount == 0 && sharedHolding ) return map.curWaitCount > 0 ? LockEventState::HasBlockingLock : LockEventState::HasLock;
        if( map.curLockCount == 0 && map.curSharedCount > 0 && waiting ) return LockEventState::WaitLock;
        return LockEventState::Nothing;
    }
}

static void SegmentPass( LockMap& map, uint16_t self, LockEvent::Type type, uint32_t idx )
{
    const bool acquire = type == LockEvent::Type::Obtain || type == LockEvent::Type::ObtainShared;

    map.passScratch.clear();
    map.passScratch.push_back( self );
    for( auto s : map.activeSlots )
    {
        if( s != self ) map.passScratch.push_back( s );
    }
    if( acquire || ( type == LockEvent::Type::Release && map.curLockCount == 0 ) )
    {
        for( auto s : map.pendingStarts )
        {
            if( s != self ) map.passScratch.push_back( s );
        }
    }

    for( auto T : map.passScratch )
    {
        auto& ti = map.threads[T];
        const bool open = ti.curState != LockEventState::Nothing;
        auto desired = ResolveLockState( map, T );
        if( open && PinnedWait( ti.curState, ti.flags ) ) desired = LockEventState::WaitLock;

        const uint8_t snapState = ( uint8_t )desired;
        const uint8_t snapFlags = ti.flags;

        if( !open )
        {
            if( desired != LockEventState::Nothing )
            {
                LockSegment seg;
                seg.evStart = idx;
                seg.nextEv = LockEvent::NoEvent;
                seg.state = snapState;
                seg.flags = snapFlags;
                ti.segments.push_back( seg );
                CacheSeverity( ti, ( uint32_t )ti.segments.size() - 1, snapState );
                ti.curState = snapState;
                if( !PinnedWait( snapState, snapFlags ) ) map.activeSlots.push_back( T );
            }
        }
        else
        {
            auto& seg = ti.segments.back();
            if( seg.state != snapState || seg.flags != snapFlags )
            {
                seg.nextEv = idx;
                ti.curState = LockEventState::Nothing;
                EraseSlot( map.activeSlots, T );
                if( desired != LockEventState::Nothing )
                {
                    LockSegment ns;
                    ns.evStart = idx;
                    ns.nextEv = LockEvent::NoEvent;
                    ns.state = snapState;
                    ns.flags = snapFlags;
                    ti.segments.push_back( ns );
                    CacheSeverity( ti, ( uint32_t )ti.segments.size() - 1, snapState );
                    ti.curState = snapState;
                    if( !PinnedWait( snapState, snapFlags ) ) map.activeSlots.push_back( T );
                }
            }
        }

        // inversion handling (traces from clients that emit the release event after the unlock):
        // an ObtainShared arriving before the exclusive Release resolves to Nothing until
        // the exclusive drains - pending so the drain event opens the hold. With the release
        // event ordered before the unlock, SharedHolding under an exclusive holder is unreachable.
        const bool need = ti.curState == LockEventState::Nothing && ( ( ti.flags & ( LockEventFlags::Waiting | LockEventFlags::SharedWaiting ) ) != 0 ||
                      ( map.legacyInversions && map.type == LockType::SharedLockable && ( ti.flags & LockEventFlags::SharedHolding ) != 0 && map.curLockCount > 0 ) );
        if( need )
        {
            if( !ti.inPending )
            {
                ti.inPending = true;
                map.pendingStarts.push_back( T );
            }
        }
        else if( ti.inPending )
        {
            ti.inPending = false;
            EraseSlot( map.pendingStarts, T );
        }
    }
}

void AppendLockEvent( LockMap& map, int64_t time, uint16_t slot, LockEvent::Type type, int16_t srcloc )
{
    if( slot == LockEvent::NoThread ) return;
    auto& ti = map.threads[slot];

    switch( type )
    {
    case LockEvent::Type::Wait:
        if( !( ti.flags & LockEventFlags::Waiting ) )
        {
            ti.flags |= LockEventFlags::Waiting;
            map.curWaitCount++;
        }
        break;
    case LockEvent::Type::WaitShared:
        if( !( ti.flags & LockEventFlags::SharedWaiting ) )
        {
            ti.flags |= LockEventFlags::SharedWaiting;
            map.curWaitSharedCount++;
        }
        break;
    case LockEvent::Type::Obtain:
        assert( map.curLockCount < UINT16_MAX );
        if( ti.flags & LockEventFlags::Waiting )
        {
            ti.flags &= ~LockEventFlags::Waiting;
            map.curWaitCount--;
        }
        if( map.curLockingThread != slot )
        {
            assert( map.legacyInversions || map.curLockCount == 0 );
            if( map.curLockCount > 0 ) map.threads[map.curLockingThread].flags &= ~LockEventFlags::LockHolding;
        }
        ti.flags |= LockEventFlags::LockHolding;
        map.curLockingThread = slot;
        map.curLockCount++;
        break;
    case LockEvent::Type::Release:
        if( map.curLockCount != 0 )
        {
            map.curLockCount--;
            if( map.curLockCount == 0 ) map.threads[map.curLockingThread].flags &= ~LockEventFlags::LockHolding;
        }
        break;
    case LockEvent::Type::ObtainShared:
        if( ti.flags & LockEventFlags::SharedWaiting )
        {
            ti.flags &= ~LockEventFlags::SharedWaiting;
            map.curWaitSharedCount--;
        }
        if( !( ti.flags & LockEventFlags::SharedHolding ) )
        {
            ti.flags |= LockEventFlags::SharedHolding;
            map.curSharedCount++;
        }
        break;
    case LockEvent::Type::ReleaseShared:
        if( ti.flags & LockEventFlags::SharedHolding )
        {
            ti.flags &= ~LockEventFlags::SharedHolding;
            map.curSharedCount--;
        }
        break;
    default:
        break;
    }

    assert( map.timeline.empty() || map.timeline.back().Time() <= time );
    assert( map.timeline.size() < LockEvent::NoEvent );
    const uint32_t idx = ( uint32_t )map.timeline.size();

    LockEvent ev;
    ev.SetTime( time );
    ev.SetSrcLoc( srcloc );
    ev.thread = slot;
    ev.type = ( uint8_t )type;
    map.timeline.push_back( ev );
    if( type == LockEvent::Type::Obtain || type == LockEvent::Type::Release )
        map.holderChanges.push_back( { idx, map.curLockingThread, map.curLockCount } );
    if( srcloc != 0 && ( ti.marks.empty() || ti.marks.back() != idx ) ) ti.marks.push_back( idx );

    if( ti.firstTime > time ) ti.firstTime = time;
    if( ti.lastTime < time ) ti.lastTime = time;

    switch( type )
    {
    case LockEvent::Type::Wait:
    case LockEvent::Type::WaitShared:
        ti.openWaitStart = time;
        ti.hasOpenWait = true;
        break;
    case LockEvent::Type::Obtain:
    case LockEvent::Type::ObtainShared:
        if( ti.hasOpenWait )
        {
            ti.waitTotal += time - ti.openWaitStart;
            ti.waitCount++;
            ti.hasOpenWait = false;
        }
        break;
    default:
        break;
    }

    switch( type )
    {
    case LockEvent::Type::Wait:
    case LockEvent::Type::Obtain:
    case LockEvent::Type::WaitShared:
    case LockEvent::Type::ObtainShared:
        ti.lastWaitObtain = idx;
        break;
    default:
        break;
    }

    if( map.curLockCount != 0 )
    {
        if( !map.holdOpen )
        {
            map.holdOpen = true;
            map.openHoldStart = time;
        }
    }
    else if( map.holdOpen )
    {
        map.holdTotal += time - map.openHoldStart;
        map.holdOpen = false;
    }

    if( map.curWaitCount != 0 )
    {
        if( !map.waitAggOpen )
        {
            map.waitAggOpen = true;
            map.openWaitAggStart = time;
        }
        if( map.curWaitCount > map.maxWaiting ) map.maxWaiting = map.curWaitCount;
    }
    else if( map.waitAggOpen )
    {
        map.waitTotalAgg += time - map.openWaitAggStart;
        map.waitAggOpen = false;
    }

    if( !map.isContended )
    {
        if( map.type == LockType::Lockable )
        {
            map.isContended = map.curLockCount != 0 && map.curWaitCount != 0;
        }
        else
        {
            map.isContended = ( map.curLockCount != 0 && ( map.curWaitCount != 0 || map.curWaitSharedCount != 0 ) ) || ( map.curSharedCount != 0 && map.curWaitCount != 0 );
        }
    }

    SegmentPass( map, slot, type, idx );
}

bool ApplyLockMark( LockMap& map, uint16_t slot, int16_t srcloc )
{
    if( slot == LockEvent::NoThread ) return false;
    auto& ti = map.threads[slot];
    const auto idx = ti.lastWaitObtain;
    if( idx == LockEvent::NoEvent ) return false;
    map.timeline[idx].SetSrcLoc( srcloc );
    if( ti.marks.empty() || ti.marks.back() != idx ) ti.marks.push_back( idx );
    return true;
}

}
