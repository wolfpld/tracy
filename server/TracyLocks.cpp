#include <utility>
#include <vector>

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

static void DetectLockDeadlocksImpl( const unordered_flat_map<uint32_t, LockMap*>& lockMap,
                                     const unordered_flat_set<uint32_t>* candidates,
                                     Vector<DeadlockGroup>& groups, Vector<DeadlockMember>& members )
{
    struct AdjEdge
    {
        uint32_t to;
        uint64_t toThread;
        uint32_t lock;
        int64_t waitTime;
    };

    unordered_flat_map<uint64_t, uint32_t> nodeIdx;
    Vector<uint64_t> nodeThread;
    std::vector<std::vector<AdjEdge>> adj;
    Vector<char> selfLoop;
    Vector<char> aux;

    auto addNode = [&] ( uint64_t thread ) -> uint32_t {
        auto it = nodeIdx.find( thread );
        if( it != nodeIdx.end() ) return it->second;
        const uint32_t idx = (uint32_t)nodeThread.size();
        nodeThread.push_back( thread );
        adj.emplace_back();
        selfLoop.push_back( 0 );
        aux.push_back( 0 );
        nodeIdx.emplace( thread, idx );
        return idx;
    };

    auto buildFor = [&] ( uint32_t lockId, const LockMap& map )
    {
        if( !map.valid || map.legacyInversions ) return;
        if( map.curWaitCount == 0 && map.curWaitSharedCount == 0 ) return;
        uint32_t sharedAux = ~0u;

        for( uint16_t s=0; s<map.threads.size(); s++ )
        {
            const auto& ti = map.threads[s];
            const bool waiting = ( ti.flags & LockEventFlags::Waiting ) != 0;
            const bool sharedWaiting = ( ti.flags & LockEventFlags::SharedWaiting ) != 0;
            if( !waiting && !sharedWaiting ) continue;

            const uint32_t from = addNode( ti.thread );
            auto addEdge = [&] ( uint16_t holder ) {
                const auto to = addNode( map.threads[holder].thread );
                adj[from].push_back( { to, map.threads[holder].thread, lockId, ti.openWaitStart } );
                if( holder == s ) selfLoop[from] = 1;
            };

            // A shared holder's exclusive wait can never be satisfied while its own
            // shared hold persists: the engine's upgrade-deadlock case, a self edge.
            if( map.type == LockType::SharedLockable && waiting && ( ti.flags & LockEventFlags::SharedHolding ) != 0 )
            {
                addEdge( s );
            }
            if( map.curLockCount != 0 )
            {
                if( map.curLockingThread != s ) addEdge( map.curLockingThread );
            }
            else if( waiting && map.curSharedCount != 0 )
            {
                // Every exclusive waiter is blocked by the whole holder set: one fact
                // about the lock, stored once as waiter->aux->holders instead of a
                // waiters x holders fan-out. The aux node only ever relays those pairs,
                // so closed rings over real threads are unchanged.
                if( sharedAux == ~0u )
                {
                    sharedAux = (uint32_t)nodeThread.size();
                    nodeThread.push_back( 0 );
                    adj.emplace_back();
                    selfLoop.push_back( 0 );
                    aux.push_back( 1 );
                    for( uint16_t h=0; h<map.threads.size(); h++ )
                    {
                        if( map.threads[h].flags & LockEventFlags::SharedHolding )
                        {
                            const auto n = addNode( map.threads[h].thread );
                            adj[sharedAux].push_back( { n, map.threads[h].thread, 0, 0 } );
                        }
                    }
                }
                adj[from].push_back( { sharedAux, 0, lockId, ti.openWaitStart } );
            }
        }
    };

    if( candidates != nullptr )
    {
        for( const auto id : *candidates )
        {
            const auto mit = lockMap.find( id );
            if( mit != lockMap.end() ) buildFor( id, *mit->second );
        }
    }
    else
    {
        for( auto& mit : lockMap ) buildFor( mit.first, *mit.second );
    }

    const uint32_t n = (uint32_t)nodeThread.size();
    if( nodeThread.empty() ) return;

    Vector<int32_t> disc;
    Vector<int32_t> low;
    Vector<char> onStack;
    disc.reserve_and_use( n );
    low.reserve_and_use( n );
    onStack.reserve_and_use( n );
    memset( disc.begin(), 0xFF, n * sizeof( int32_t ) );
    memset( low.begin(), 0, n * sizeof( int32_t ) );
    memset( onStack.begin(), 0, n );
    Vector<uint32_t> stack;
    Vector<uint32_t> comp;
    Vector<char> inComp;
    inComp.reserve_and_use( n );
    memset( inComp.begin(), 0, n );
    int32_t clk = 0;

    struct Frame
    {
        uint32_t v;
        size_t ei;
    };
    Vector<Frame> rstack;

    for( uint32_t root=0; root<n; root++ )
    {
        if( disc[root] >= 0 ) continue;
        disc[root] = low[root] = clk++;
        stack.push_back( root );
        onStack[root] = 1;
        rstack.push_back( { root, 0 } );
        while( !rstack.empty() )
        {
            const uint32_t v = rstack.back().v;
            if( rstack.back().ei < adj[v].size() )
            {
                const auto e = adj[v][rstack.back().ei++];
                if( disc[e.to] < 0 )
                {
                    disc[e.to] = low[e.to] = clk++;
                    stack.push_back( e.to );
                    onStack[e.to] = 1;
                    rstack.push_back( { e.to, 0 } );
                }
                else if( onStack[e.to] && disc[e.to] < low[v] )
                {
                    low[v] = disc[e.to];
                }
            }
            else
            {
                rstack.pop_back();
                if( !rstack.empty() && low[v] < low[rstack.back().v] ) low[rstack.back().v] = low[v];
                if( low[v] != disc[v] ) continue;

                comp.clear();
                uint32_t w;
                do
                {
                    w = stack.back();
                    stack.pop_back();
                    onStack[w] = 0;
                    comp.push_back( w );
                } while( w != v );

                uint32_t real = 0;
                bool auxInComp = false;
                for( auto c : comp )
                {
                    if( aux[c] != 0 ) auxInComp = true;
                    else real++;
                }
                // Aux is only a relay: one real thread closing its ring through aux is
                // waiting on a lock held also by itself - an upgrade self-deadlock.
                if( real < 2 && !( real == 1 && ( auxInComp || selfLoop[v] ) ) ) continue;

                for( auto c : comp ) inComp[c] = 1;

                const uint32_t first = (uint32_t)members.size();
                int64_t time = 0;
                for( auto c : comp )
                {
                    if( aux[c] != 0 ) continue;
                    for( auto& e : adj[c] )
                    {
                        if( !inComp[e.to] ) continue;
                        uint32_t blocker = e.to;
                        if( aux[e.to] != 0 )
                        {
                            bool found = false;
                            for( auto& he : adj[e.to] )
                            {
                                if( inComp[he.to] != 0 ) { blocker = he.to; found = true; break; }
                            }
                            if( !found ) continue;
                        }
                        members.push_back( { nodeThread[c], nodeThread[blocker], e.lock, e.waitTime } );
                        if( e.waitTime > time ) time = e.waitTime;
                        break;
                    }
                }
                const uint32_t cnt = (uint32_t)members.size() - first;
                std::sort( members.begin()+first, members.begin()+first+cnt, [] ( const DeadlockMember& lhs, const DeadlockMember& rhs ) { return lhs.thread < rhs.thread; } );
                groups.push_back( { time, first, cnt } );

                for( auto c : comp ) inComp[c] = 0;
            }
        }
    }
}

void DetectLockDeadlocks( const unordered_flat_map<uint32_t, LockMap*>& lockMap,
                          Vector<DeadlockGroup>& groups, Vector<DeadlockMember>& members )
{
    DetectLockDeadlocksImpl( lockMap, nullptr, groups, members );
}

void DetectLockDeadlocks( const unordered_flat_map<uint32_t, LockMap*>& lockMap,
                          const unordered_flat_set<uint32_t>& candidates,
                          Vector<DeadlockGroup>& groups, Vector<DeadlockMember>& members )
{
    DetectLockDeadlocksImpl( lockMap, &candidates, groups, members );
}

}
