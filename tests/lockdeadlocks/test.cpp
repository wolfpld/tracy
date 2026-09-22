#include <algorithm>
#include <assert.h>
#include <stdio.h>

#include "TracyLocks.hpp"

using namespace tracy;

static constexpr uint64_t TA = 100;
static constexpr uint64_t TB = 200;
static constexpr uint64_t TC = 300;
static constexpr uint64_t TD = 400;
static constexpr uint32_t L1 = 1;
static constexpr uint32_t L2 = 2;
static constexpr uint32_t L3 = 3;
static constexpr uint32_t L4 = 4;

struct Fixture
{
    unordered_flat_map<uint32_t, LockMap*> maps;

    LockMap& Make( uint32_t id, LockType type, bool legacy = false )
    {
        auto lm = new LockMap();
        InitLockMap( *lm, 0, type, 0 );
        lm->legacyInversions = legacy;
        maps.emplace( id, lm );
        return *lm;
    }

    ~Fixture()
    {
        for( auto& v : maps ) delete v.second;
    }
};

static void Ev( LockMap& lm, int64_t t, uint64_t thread, LockEvent::Type type )
{
    const auto slot = GetLockSlot( lm, thread );
    AppendLockEvent( lm, t, slot, type );
}

struct Result
{
    Vector<DeadlockGroup> groups;
    Vector<DeadlockMember> members;
};

static Result Run( const char* name, Fixture& f )
{
    printf( "%s... ", name );
    fflush( stdout );
    Result r;
    DetectLockDeadlocks( f.maps, r.groups, r.members );
    return r;
}

static bool HasThread( const Result& r, size_t group, uint64_t thread )
{
    const auto& g = r.groups[group];
    for( uint32_t i=0; i<g.cnt; i++ )
        if( r.members[g.first+i].thread == thread ) return true;
    return false;
}

static const DeadlockMember* Member( const Result& r, size_t group, uint64_t thread )
{
    const auto& g = r.groups[group];
    for( uint32_t i=0; i<g.cnt; i++ )
        if( r.members[g.first+i].thread == thread ) return &r.members[g.first+i];
    return nullptr;
}

static void CheckGroup( const Result& r, size_t group, std::initializer_list<uint64_t> threads )
{
    const auto& g = r.groups[group];
    assert( g.cnt == threads.size() );
    for( auto t : threads ) assert( HasThread( r, group, t ) );
}

int main()
{
    // Crossed exclusive locks: the classic two-thread deadlock.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::Lockable );
        auto& l2 = f.Make( L2, LockType::Lockable );
        Ev( l1, 10, TA, LockEvent::Type::Obtain );
        Ev( l2, 20, TB, LockEvent::Type::Obtain );
        Ev( l2, 30, TA, LockEvent::Type::Wait );
        Ev( l1, 40, TB, LockEvent::Type::Wait );
        const auto r = Run( "crossed two-lock deadlock", f );
        assert( r.groups.size() == 1 );
        CheckGroup( r, 0, { TA, TB } );
        assert( r.groups[0].time == 40 );
        const auto* ma = Member( r, 0, TA );
        const auto* mb = Member( r, 0, TB );
        assert( ma && ma->lock == L2 && ma->holder == TB && ma->waitTime == 30 );
        assert( mb && mb->lock == L1 && mb->holder == TA && mb->waitTime == 40 );
        printf( "ok\n" );
    }

    // Contention without a cycle is not a deadlock.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::Lockable );
        Ev( l1, 10, TA, LockEvent::Type::Obtain );
        Ev( l1, 20, TB, LockEvent::Type::Wait );
        assert( Run( "simple contention", f ).groups.size() == 0 );
        printf( "ok\n" );
    }

    // A recursive acquire window: the thread is its own exclusive holder. Recursion is
    // indistinguishable from self-deadlock, so nothing is reported.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::Lockable );
        Ev( l1, 10, TA, LockEvent::Type::Obtain );
        Ev( l1, 20, TA, LockEvent::Type::Wait );
        assert( Run( "recursive acquire window", f ).groups.size() == 0 );
        printf( "ok\n" );
    }

    // A shared holder waiting for exclusive can never progress while its own shared hold persists.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::SharedLockable );
        Ev( l1, 10, TA, LockEvent::Type::ObtainShared );
        Ev( l1, 20, TA, LockEvent::Type::Wait );
        const auto r = Run( "upgrade self-deadlock", f );
        assert( r.groups.size() == 1 );
        CheckGroup( r, 0, { TA } );
        const auto* ma = Member( r, 0, TA );
        assert( ma && ma->holder == TA );
        printf( "ok\n" );
    }

    // Two shared holders both requesting exclusive: one group, both members.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::SharedLockable );
        Ev( l1, 10, TA, LockEvent::Type::ObtainShared );
        Ev( l1, 15, TB, LockEvent::Type::ObtainShared );
        Ev( l1, 20, TA, LockEvent::Type::Wait );
        Ev( l1, 25, TB, LockEvent::Type::Wait );
        const auto r = Run( "mutual upgrade", f );
        assert( r.groups.size() == 1 );
        CheckGroup( r, 0, { TA, TB } );
        printf( "ok\n" );
    }

    // A blocked exclusive waiter behind shared holders that keep running is contention, not deadlock.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::SharedLockable );
        Ev( l1, 10, TA, LockEvent::Type::ObtainShared );
        Ev( l1, 20, TB, LockEvent::Type::Wait );
        assert( Run( "exclusive waiter behind live shared holders", f ).groups.size() == 0 );
        printf( "ok\n" );
    }

    // Exclusive waiter blocked by a shared holder; that holder waits on the first thread's lock.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::SharedLockable );
        auto& l2 = f.Make( L2, LockType::Lockable );
        Ev( l1, 10, TA, LockEvent::Type::ObtainShared );
        Ev( l2, 20, TB, LockEvent::Type::Obtain );
        Ev( l2, 30, TA, LockEvent::Type::Wait );
        Ev( l1, 40, TB, LockEvent::Type::Wait );
        const auto r = Run( "cycle through shared hold", f );
        assert( r.groups.size() == 1 );
        CheckGroup( r, 0, { TA, TB } );
        printf( "ok\n" );
    }

    // Chains that terminate at a running thread never close.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::Lockable );
        auto& l2 = f.Make( L2, LockType::Lockable );
        Ev( l1, 10, TA, LockEvent::Type::Obtain );
        Ev( l1, 20, TB, LockEvent::Type::Wait );
        Ev( l2, 30, TC, LockEvent::Type::Obtain );
        Ev( l2, 40, TA, LockEvent::Type::Wait );
        assert( Run( "chain to live holder", f ).groups.size() == 0 );
        printf( "ok\n" );
    }

    // Three-thread cycle forms a single group.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::Lockable );
        auto& l2 = f.Make( L2, LockType::Lockable );
        auto& l3 = f.Make( L3, LockType::Lockable );
        Ev( l1, 10, TA, LockEvent::Type::Obtain );
        Ev( l2, 15, TB, LockEvent::Type::Obtain );
        Ev( l3, 20, TC, LockEvent::Type::Obtain );
        Ev( l2, 30, TA, LockEvent::Type::Wait );
        Ev( l3, 40, TB, LockEvent::Type::Wait );
        Ev( l1, 50, TC, LockEvent::Type::Wait );
        const auto r = Run( "three-thread cycle", f );
        assert( r.groups.size() == 1 );
        CheckGroup( r, 0, { TA, TB, TC } );
        assert( r.groups[0].time == 50 );
        printf( "ok\n" );
    }

    // Independent deadlocks are reported as separate groups.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::Lockable );
        auto& l2 = f.Make( L2, LockType::Lockable );
        auto& l3 = f.Make( L3, LockType::Lockable );
        auto& l4 = f.Make( L4, LockType::Lockable );
        Ev( l1, 10, TA, LockEvent::Type::Obtain );
        Ev( l2, 15, TB, LockEvent::Type::Obtain );
        Ev( l3, 20, TC, LockEvent::Type::Obtain );
        Ev( l4, 25, TD, LockEvent::Type::Obtain );
        Ev( l2, 30, TA, LockEvent::Type::Wait );
        Ev( l1, 35, TB, LockEvent::Type::Wait );
        Ev( l4, 40, TC, LockEvent::Type::Wait );
        Ev( l3, 45, TD, LockEvent::Type::Wait );
        const auto r = Run( "two disjoint cycles", f );
        assert( r.groups.size() == 2 );
        assert( ( HasThread( r, 0, TA ) && HasThread( r, 1, TC ) ) || ( HasThread( r, 0, TC ) && HasThread( r, 1, TA ) ) );
        printf( "ok\n" );
    }

    // Traces with release-ordering inversions have ambiguous holder state; they are excluded.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::Lockable, true );
        auto& l2 = f.Make( L2, LockType::Lockable, true );
        Ev( l1, 10, TA, LockEvent::Type::Obtain );
        Ev( l2, 20, TB, LockEvent::Type::Obtain );
        Ev( l2, 30, TA, LockEvent::Type::Wait );
        Ev( l1, 40, TB, LockEvent::Type::Wait );
        assert( Run( "legacy inversion exclusion", f ).groups.size() == 0 );
        printf( "ok\n" );
    }

    // A wait with no holder and no co-waiters has no edge to follow.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::Lockable );
        Ev( l1, 10, TA, LockEvent::Type::Wait );
        assert( Run( "wait without holder", f ).groups.size() == 0 );
        printf( "ok\n" );
    }

    // Releasing one leg of a cycle dissolves it; final-state scans reflect the resolution.
    {
        Fixture f;
        auto& l1 = f.Make( L1, LockType::Lockable );
        auto& l2 = f.Make( L2, LockType::Lockable );
        Ev( l1, 10, TA, LockEvent::Type::Obtain );
        Ev( l2, 20, TB, LockEvent::Type::Obtain );
        Ev( l2, 30, TA, LockEvent::Type::Wait );
        Ev( l1, 40, TB, LockEvent::Type::Wait );
        assert( Run( "cycle resolved by release", f ).groups.size() == 1 );
        Ev( l1, 50, TA, LockEvent::Type::Release );
        Result r2;
        DetectLockDeadlocks( f.maps, r2.groups, r2.members );
        assert( r2.groups.size() == 0 );
        printf( "ok\n" );
    }

    // Exclusive waiters behind several shared holders: no ring when all holders run free.
    {
        Fixture f;
        auto& rw = f.Make( L1, LockType::SharedLockable );
        Ev( rw, 10, TA, LockEvent::Type::ObtainShared );
        Ev( rw, 11, TB, LockEvent::Type::ObtainShared );
        for( uint64_t w = 0; w < 10; w++ ) Ev( rw, 20 + w, 200 + w, LockEvent::Type::Wait );
        assert( Run( "convoy without cycle", f ).groups.size() == 0 );
        printf( "ok\n" );
    }

    // A convoy closes its ring through one shared holder; free holders and co-waiters are not members.
    {
        Fixture f;
        auto& rw = f.Make( L1, LockType::SharedLockable );
        auto& m = f.Make( L2, LockType::Lockable );
        Ev( rw, 10, TA, LockEvent::Type::ObtainShared );
        Ev( rw, 11, TB, LockEvent::Type::ObtainShared );
        Ev( m, 15, TC, LockEvent::Type::Obtain );
        Ev( rw, 20, TC, LockEvent::Type::Wait );
        Ev( rw, 21, TD, LockEvent::Type::Wait );
        Ev( m, 25, TB, LockEvent::Type::Wait );
        const auto r = Run( "cycle through shared holder", f );
        assert( r.groups.size() == 1 );
        assert( r.groups[0].cnt == 2 );
        assert( HasThread( r, 0, TC ) && HasThread( r, 0, TB ) );
        assert( !HasThread( r, 0, TA ) && !HasThread( r, 0, TD ) );
        const auto* mc = Member( r, 0, TC );
        assert( mc && mc->holder == TB && mc->lock == L1 );
        const auto* mt = Member( r, 0, TB );
        assert( mt && mt->holder == TC && mt->lock == L2 );
        printf( "ok\n" );
    }

    // A shared holder waiting for exclusive is deadlocked by its own hold also when others hold shared.
    {
        Fixture f;
        auto& rw = f.Make( L1, LockType::SharedLockable );
        Ev( rw, 10, TA, LockEvent::Type::ObtainShared );
        Ev( rw, 11, TB, LockEvent::Type::ObtainShared );
        Ev( rw, 12, TA, LockEvent::Type::Wait );
        const auto r = Run( "upgrade with co-holders", f );
        assert( r.groups.size() == 1 );
        assert( r.groups[0].cnt == 1 );
        const auto* ma = Member( r, 0, TA );
        assert( ma && ma->holder == TA && ma->lock == L1 );
        printf( "ok\n" );
    }

    printf( "All deadlock detection tests passed.\n" );
    return 0;
}
