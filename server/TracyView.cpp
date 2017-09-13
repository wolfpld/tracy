#ifdef _MSC_VER
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

#include <assert.h>

#include "../common/TracySocket.hpp"
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

bool View::ShouldExit()
{
    return s_instance->m_shutdown.load( std::memory_order_relaxed );
}

void View::Worker()
{
    Socket sock;

    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    for(;;)
    {
        if( m_shutdown.load( std::memory_order_relaxed ) ) return;
        if( !sock.Connect( m_addr.c_str(), "8086" ) ) continue;

        uint8_t lz4;

        if( !sock.Read( &m_timeBegin, sizeof( m_timeBegin ), &tv, ShouldExit ) ) goto close;
        if( !sock.Read( &lz4, sizeof( lz4 ), &tv, ShouldExit ) ) goto close;

        for(;;)
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;
            char buf[16*1024];
            if( sock.Recv( buf, 16*1024, &tv ) == 0 ) break;
        }

close:
        sock.Close();
    }
}

}
