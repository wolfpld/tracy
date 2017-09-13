#ifdef _MSC_VER
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

#include <assert.h>

#include "../common/tracy_lz4.hpp"
#include "../common/TracyProtocol.hpp"
#include "../common/TracySocket.hpp"
#include "../common/TracySystem.hpp"
#include "../common/TracyQueue.hpp"
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
    m_shutdown.store( true, std::memory_order_relaxed );
    m_thread.join();

    assert( s_instance != nullptr );
    s_instance = nullptr;
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

            if( lz4 )
            {
                char buf[TargetFrameSize];
                char lz4buf[LZ4Size];
                lz4sz_t lz4sz;
                if( !sock.Read( &lz4sz, sizeof( lz4sz ), &tv, ShouldExit ) ) goto close;
                if( !sock.Read( lz4buf, lz4sz, &tv, ShouldExit ) ) goto close;

                auto sz = LZ4_decompress_safe( lz4buf, buf, lz4sz, TargetFrameSize );
                assert( sz >= 0 );

                const char* ptr = buf;
                const char* end = buf + sz;
                while( ptr < end )
                {
                    auto ev = (QueueItem*)ptr;
                    Process( *ev );
                    ptr += QueueDataSize[(uint8_t)ev->hdr.type];
                }
            }
            else
            {
                QueueItem hdr;
                if( !sock.Read( &hdr.hdr, sizeof( QueueHeader ), &tv, ShouldExit ) ) goto close;
                if( !sock.Read( ((char*)&hdr) + sizeof( QueueHeader ), QueueDataSize[(uint8_t)hdr.hdr.type] - sizeof( QueueHeader ), &tv, ShouldExit ) ) goto close;
                Process( hdr );
            }
        }

close:
        sock.Close();
    }
}

void View::Process( const QueueItem& ev )
{

}

}
