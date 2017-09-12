#include <assert.h>
#include <chrono>
#include <limits>
#include <memory>

#include "../common/tracy_lz4.hpp"
#include "../common/TracySocket.hpp"
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
    QueueItem item;
    item.hdr.type = QueueType::ZoneBegin;
    item.hdr.time = GetTime();
    item.zoneBegin = std::move( data );
    s_instance->m_queue.enqueue( GetToken(), std::move( item ) );
}

void Profiler::ZoneEnd( QueueZoneEnd&& data )
{
    QueueItem item;
    item.hdr.type = QueueType::ZoneEnd;
    item.hdr.time = GetTime();
    item.zoneEnd = std::move( data );
    s_instance->m_queue.enqueue( GetToken(), std::move( item ) );
}

Profiler* Profiler::Instance()
{
    return s_instance;
}

void Profiler::Worker()
{
    enum { TargetFrameSize = 64000 };
    enum { BulkSize = TargetFrameSize / QueueItemSize };
    enum { LZ4Size = LZ4_COMPRESSBOUND( TargetFrameSize ) };
    static_assert( LZ4Size <= std::numeric_limits<uint16_t>::max(), "LZ4Size greater than uint16_t" );

    moodycamel::ConsumerToken token( m_queue );

    ListenSocket listen;
    listen.Listen( "8086", 8 );

    for(;;)
    {
        std::unique_ptr<Socket> sock;
        for(;;)
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;
            sock = listen.Accept();
            if( sock ) break;
        }

        sock->Send( &m_timeBegin, sizeof( m_timeBegin ) );
#ifdef _DEBUG
        // notify client that lz4 compression is disabled (too slow in debug builds)
        char val = 0;
        sock->Send( &val, 1 );
#else
        char val = 1;
        sock->Send( &val, 1 );
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
                    const auto dsz = QueueDataSize[(uint8_t)item[i].hdr.type];
                    memcpy( ptr, item+i, dsz );
                    ptr += dsz;
                }
#ifdef _DEBUG
                if( sock->Send( buf, ptr - buf ) == -1 ) break;
#else
                char lz4[LZ4Size + sizeof( uint16_t )];
                const uint16_t lz4sz = LZ4_compress_default( buf, lz4+2, ptr - buf, LZ4Size );
                memcpy( lz4, &lz4sz, sizeof( uint16_t ) );
                if( sock->Send( lz4, lz4sz ) == -1 ) break;
#endif
            }
            else
            {
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }
        }
    }
}

}
