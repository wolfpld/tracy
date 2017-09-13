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

        auto left = sizeof( m_timeBegin );
        auto ptr = (char*)&m_timeBegin;
        do
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;
            auto sz = sock.Recv( ptr, left, &tv );
            if( sz == 0 ) goto close;
            if( sz > 0 )
            {
                left -= sz;
                ptr += sz;
            }
        }
        while( left > 0 );

        uint8_t lz4;
        while( sock.Recv( &lz4, 1, nullptr ) == -1 )
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;
        }

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
