#include <assert.h>

#include "TracyProfiler.hpp"
#include "TracySystem.hpp"

namespace tracy
{

static Profiler* s_instance = nullptr;

Profiler::Profiler()
    : m_shutdown( false )
{
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

void Profiler::Worker()
{
    for(;;)
    {
        if( m_shutdown.load( std::memory_order_relaxed ) ) return;
    }
}

}
