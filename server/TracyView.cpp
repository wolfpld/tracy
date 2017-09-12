#include <assert.h>

#include "../common/TracySystem.hpp"
#include "TracyView.hpp"

namespace tracy
{

static View* s_instance = nullptr;

View::View( const char* addr )
    : m_addr( addr )
    , m_shutdown( false )
{
    assert( s_instance == nullptr );
    s_instance = this;

    m_thread = std::thread( [this] { Worker(); } );
    SetThreadName( m_thread, "Tracy View" );
}

View::~View()
{
    assert( s_instance != nullptr );
    s_instance = nullptr;

    m_shutdown.store( true, std::memory_order_relaxed );
    m_thread.join();
}

void View::Worker()
{
    for(;;)
    {
        if( m_shutdown.load( std::memory_order_relaxed ) ) return;
        std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
    }
}

}
