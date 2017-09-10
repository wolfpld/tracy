#include <assert.h>
#include <chrono>

#include "TracyProfiler.hpp"
#include "TracySystem.hpp"

namespace tracy
{

extern const char* PointerCheckA;
const char* PointerCheckB = "tracy";

static inline int64_t GetTime()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
}


static Profiler* s_instance = nullptr;

Profiler::Profiler()
    : m_timeBegin( GetTime() )
    , m_shutdown( false )
    , m_id( 0 )
{
    assert( PointerCheckA == PointerCheckB );
    assert( !s_instance );
    s_instance = this;

    m_thread = std::thread( [this] { Worker(); } );
    SetThreadName( m_thread, "Tracy Profiler" );
}

Profiler::~Profiler()
{
    assert( s_instance );
    s_instance = nullptr;

    m_shutdown.store( true, std::memory_order_relaxed );
    m_thread.join();
}

uint64_t Profiler::GetNewId()
{
    return s_instance->m_id.fetch_add( 1, std::memory_order_relaxed );
}

void Profiler::ZoneBegin( QueueZoneBegin&& data )
{
    QueueItem item { QueueType::ZoneBegin, GetTime() };
    item.zoneBegin = std::move( data );
    s_instance->m_queue.enqueue( GetToken(), std::move( item ) );
}

void Profiler::ZoneEnd( QueueZoneEnd&& data )
{
    QueueItem item { QueueType::ZoneEnd, GetTime() };
    item.zoneEnd = std::move( data );
    s_instance->m_queue.enqueue( GetToken(), std::move( item ) );
}

Profiler* Profiler::Instance()
{
    return s_instance;
}

void Profiler::Worker()
{
    enum { BulkSize = 1024 };
    moodycamel::ConsumerToken token( m_queue );

    for(;;)
    {
        if( m_shutdown.load( std::memory_order_relaxed ) ) return;

        QueueItem item[BulkSize];
        const auto sz = m_queue.try_dequeue_bulk( token, item, BulkSize );
        if( sz > 0 )
        {
        }
        else
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
        }
    }
}

}
