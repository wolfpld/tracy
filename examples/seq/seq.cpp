// Demonstrates Tracy's sequence (async-continuation) feature.
//
// Submits a mix of four "recipes" — different async pipelines with varying
// chain lengths and per-stage work — onto a thread pool. Each pipeline kicks
// off on the main thread (via TracySeqCreate + a tiny setup stage) and then
// migrates through 2-7 continuations on worker threads. The profiler renders
// arrows between suspend/resume points so the cross-thread chain of any one
// pipeline is visible by hovering its zones.
//
// Build:
//   make
//
// Run:
//   ./seq        # then connect tracy-profiler

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "Tracy.hpp"

using namespace std::chrono_literals;

class ThreadPool
{
public:
    explicit ThreadPool( int n )
    {
        for( int i = 0; i < n; ++i )
        {
            m_workers.emplace_back( [this, i]
            {
                char name[16];
                std::snprintf( name, sizeof( name ), "worker-%d", i );
                tracy::SetThreadName( name );
                Run();
            } );
        }
    }

    ~ThreadPool()
    {
        {
            std::lock_guard<std::mutex> lk( m_mu );
            m_stop = true;
        }
        m_cv.notify_all();
        for( auto& w : m_workers ) w.join();
    }

    void Submit( std::function<void()> task )
    {
        {
            std::lock_guard<std::mutex> lk( m_mu );
            m_queue.push( std::move( task ) );
        }
        m_cv.notify_one();
    }

private:
    void Run()
    {
        for(;;)
        {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lk( m_mu );
                m_cv.wait( lk, [this]{ return m_stop || !m_queue.empty(); } );
                if( m_stop && m_queue.empty() ) return;
                task = std::move( m_queue.front() );
                m_queue.pop();
            }
            task();
        }
    }

    std::mutex m_mu;
    std::condition_variable m_cv;
    std::queue<std::function<void()>> m_queue;
    std::vector<std::thread> m_workers;
    bool m_stop = false;
};

struct Chain
{
    uint64_t seq;
    int value;
    ThreadPool* pool;
    std::atomic<int>* remaining;
};

// Each stage opens its own ZoneScoped, brackets simulated work with
// TracySeqResume/Suspend, then either submits the next stage to the pool or
// (for terminal stages) calls TracySeqRetire and bumps the completion counter.

// ============================================================================
// query: 2 stages — short pipeline, tight chain
// ============================================================================

static void query_exec( Chain c )
{
    ZoneScopedN( "query/exec" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 35ms );
    c.value *= 3;
    TracySeqSuspend( c.seq );
    TracySeqRetire( c.seq );
    c.remaining->fetch_sub( 1, std::memory_order_release );
}

static void query_parse( Chain c )
{
    ZoneScopedN( "query/parse" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 8ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ query_exec( c ); } );
}

// ============================================================================
// ingest: 4 stages — IO-heavy
// ============================================================================

static void ingest_store( Chain c )
{
    ZoneScopedN( "ingest/store" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 18ms );
    TracySeqSuspend( c.seq );
    TracySeqRetire( c.seq );
    c.remaining->fetch_sub( 1, std::memory_order_release );
}

static void ingest_validate( Chain c )
{
    ZoneScopedN( "ingest/validate" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 22ms );
    c.value += 1;
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ ingest_store( c ); } );
}

static void ingest_parse( Chain c )
{
    ZoneScopedN( "ingest/parse" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 28ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ ingest_validate( c ); } );
}

static void ingest_fetch( Chain c )
{
    ZoneScopedN( "ingest/fetch" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 60ms );    // slow IO
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ ingest_parse( c ); } );
}

// ============================================================================
// render: 5 stages — frame-like workload
// ============================================================================

static void render_present( Chain c )
{
    ZoneScopedN( "render/present" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 10ms );
    TracySeqSuspend( c.seq );
    TracySeqRetire( c.seq );
    c.remaining->fetch_sub( 1, std::memory_order_release );
}

static void render_compose( Chain c )
{
    ZoneScopedN( "render/compose" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 35ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ render_present( c ); } );
}

static void render_shadows( Chain c )
{
    ZoneScopedN( "render/shadows" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 45ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ render_compose( c ); } );
}

static void render_geometry( Chain c )
{
    ZoneScopedN( "render/geometry" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 55ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ render_shadows( c ); } );
}

static void render_setup( Chain c )
{
    ZoneScopedN( "render/setup" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 12ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ render_geometry( c ); } );
}

// ============================================================================
// compile: 7 stages — long pipeline
// ============================================================================

static void compile_emit( Chain c )
{
    ZoneScopedN( "compile/emit" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 12ms );
    TracySeqSuspend( c.seq );
    TracySeqRetire( c.seq );
    c.remaining->fetch_sub( 1, std::memory_order_release );
}

static void compile_codegen( Chain c )
{
    ZoneScopedN( "compile/codegen" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 40ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ compile_emit( c ); } );
}

static void compile_optimize( Chain c )
{
    ZoneScopedN( "compile/optimize" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 70ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ compile_codegen( c ); } );
}

static void compile_ir( Chain c )
{
    ZoneScopedN( "compile/ir" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 25ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ compile_optimize( c ); } );
}

static void compile_typecheck( Chain c )
{
    ZoneScopedN( "compile/typecheck" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 30ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ compile_ir( c ); } );
}

static void compile_parse( Chain c )
{
    ZoneScopedN( "compile/parse" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 18ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ compile_typecheck( c ); } );
}

static void compile_lex( Chain c )
{
    ZoneScopedN( "compile/lex" );
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 8ms );
    TracySeqSuspend( c.seq );
    c.pool->Submit( [c]{ compile_parse( c ); } );
}

// ============================================================================
// Kick off a chain from the main thread. The "kickoff" zone holds the
// TracySeqCreate plus a small setup window on main; the first worker stage
// fires when its Submit lands on a worker.
// ============================================================================

enum class Recipe { Query, Ingest, Render, Compile };

static void Kickoff( Recipe r, int value, ThreadPool& pool, std::atomic<int>& remaining )
{
    ZoneScopedN( "kickoff" );
    Chain c {
        .seq       = TracySeqCreate(),
        .value     = value,
        .pool      = &pool,
        .remaining = &remaining,
    };
    TracySeqResume( c.seq );
    std::this_thread::sleep_for( 4ms );
    TracySeqSuspend( c.seq );

    switch( r )
    {
    case Recipe::Query:   pool.Submit( [c]{ query_parse( c ); } );   break;
    case Recipe::Ingest:  pool.Submit( [c]{ ingest_fetch( c ); } );  break;
    case Recipe::Render:  pool.Submit( [c]{ render_setup( c ); } );  break;
    case Recipe::Compile: pool.Submit( [c]{ compile_lex( c ); } );   break;
    }
}

int main()
{
    tracy::SetThreadName( "main" );

    ThreadPool pool( 6 );

    // Mixed schedule: short and long pipelines interleaved so workers stay
    // saturated and continuations naturally bounce across threads.
    static constexpr Recipe schedule[] = {
        Recipe::Compile, Recipe::Query,   Recipe::Ingest,  Recipe::Render,
        Recipe::Query,   Recipe::Compile, Recipe::Render,  Recipe::Ingest,
        Recipe::Render,  Recipe::Query,   Recipe::Compile, Recipe::Ingest,
        Recipe::Query,   Recipe::Render,  Recipe::Ingest,  Recipe::Compile,
        Recipe::Query,   Recipe::Compile, Recipe::Render,  Recipe::Query,
    };
    constexpr int kChains = sizeof( schedule ) / sizeof( schedule[0] );
    std::atomic<int> remaining{ kChains };

    for( int i = 0; i < kChains; ++i )
    {
        FrameMarkNamed( "submit" );
        Kickoff( schedule[i], i * 100, pool, remaining );
        std::this_thread::sleep_for( 6ms );
    }

    while( remaining.load( std::memory_order_acquire ) > 0 )
    {
        std::this_thread::sleep_for( 10ms );
    }

    std::printf( "%d chains done\n", kChains );
    return 0;
}
