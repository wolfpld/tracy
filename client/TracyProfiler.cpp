#ifdef _MSC_VER
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

#include <assert.h>
#include <memory>
#include <limits>

#include "../common/tracy_lz4.hpp"
#include "../common/TracyProtocol.hpp"
#include "../common/TracySocket.hpp"
#include "../common/TracySystem.hpp"
#include "TracyProfiler.hpp"

#ifdef _DEBUG
#  define DISABLE_LZ4
#endif

namespace tracy
{

extern const char* PointerCheckA;
const char* PointerCheckB = "tracy";


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
    m_shutdown.store( true, std::memory_order_relaxed );
    m_thread.join();

    assert( s_instance );
    s_instance = nullptr;

}

uint64_t Profiler::GetNewId()
{
    return s_instance->m_id.fetch_add( 1, std::memory_order_relaxed );
}

uint64_t Profiler::ZoneBegin( QueueZoneBegin&& data )
{
    auto id = GetNewId();
    QueueItem item;
    item.hdr.type = QueueType::ZoneBegin;
    item.hdr.id = id;
    item.zoneBegin = std::move( data );
    s_instance->m_queue.enqueue( GetToken(), std::move( item ) );
    return id;
}

void Profiler::ZoneEnd( uint64_t id, QueueZoneEnd&& data )
{
    QueueItem item;
    item.hdr.type = QueueType::ZoneEnd;
    item.hdr.id = id;
    item.zoneEnd = std::move( data );
    s_instance->m_queue.enqueue( GetToken(), std::move( item ) );
}

Profiler* Profiler::Instance()
{
    return s_instance;
}

bool Profiler::ShouldExit()
{
    return s_instance->m_shutdown.load( std::memory_order_relaxed );
}

void Profiler::Worker()
{
    enum { BulkSize = TargetFrameSize / QueueItemSize };

    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    moodycamel::ConsumerToken token( m_queue );

    ListenSocket listen;
    listen.Listen( "8086", 8 );

    for(;;)
    {
        for(;;)
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;
            m_sock = listen.Accept();
            if( m_sock ) break;
        }

        m_sock->Send( &m_timeBegin, sizeof( m_timeBegin ) );
#ifdef DISABLE_LZ4
        // notify client that lz4 compression is disabled (too slow in debug builds)
        char val = 0;
        m_sock->Send( &val, 1 );
#else
        char val = 1;
        m_sock->Send( &val, 1 );
#endif

        for(;;)
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;

            QueueItem item[BulkSize];
            const auto sz = m_queue.try_dequeue_bulk( token, item, BulkSize );
            if( sz > 0 )
            {
                char buf[TargetFrameSize];
                char* ptr = buf;
                for( int i=0; i<sz; i++ )
                {
                    const auto dsz = QueueDataSize[item[i].hdr.idx];
                    memcpy( ptr, item+i, dsz );
                    ptr += dsz;
                }
                if( !SendData( buf, ptr - buf ) ) break;
            }
            else
            {
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }

            while( m_sock->HasData() )
            {
                uint64_t ptr;
                if( !m_sock->Read( &ptr, sizeof( ptr ), &tv, ShouldExit ) ) break;
                SendString( ptr );
            }
        }
    }
}

bool Profiler::SendData( const char* data, size_t len )
{
#ifdef DISABLE_LZ4
    if( m_sock->Send( data, len ) == -1 ) return false;
#else
    char lz4[LZ4Size + sizeof( lz4sz_t )];
    const lz4sz_t lz4sz = LZ4_compress_default( data, lz4 + sizeof( lz4sz_t ), len, LZ4Size );
    memcpy( lz4, &lz4sz, sizeof( lz4sz ) );
    if( m_sock->Send( lz4, lz4sz + sizeof( lz4sz_t ) ) == -1 ) return false;
#endif
    return true;
}

bool Profiler::SendString( uint64_t str )
{
    auto ptr = (const char*)str;

    QueueHeader hdr;
    hdr.type = QueueType::StringData;
    hdr.id = str;

    char buf[TargetFrameSize];
    memcpy( buf, &hdr, sizeof( hdr ) );

    auto len = strlen( ptr );
    assert( len < TargetFrameSize - sizeof( hdr ) - sizeof( uint16_t ) );
    assert( len <= std::numeric_limits<uint16_t>::max() );
    uint16_t l16 = len;
    memcpy( buf + sizeof( hdr ), &l16, sizeof( l16 ) );
    memcpy( buf + sizeof( hdr ) + sizeof( l16 ), ptr, l16 );

    return SendData( buf, sizeof( hdr ) + sizeof( l16 ) + l16 );
}

}
