#ifdef _MSC_VER
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

#include <assert.h>
#include <chrono>
#include <limits>
#include <memory>
#include <string.h>

#include "../common/TracyProtocol.hpp"
#include "../common/TracySocket.hpp"
#include "../common/TracySystem.hpp"
#include "concurrentqueue.h"
#include "TracyProfiler.hpp"
#include "TracyThread.hpp"

#ifdef _DEBUG
#  define DISABLE_LZ4
#endif

namespace tracy
{

static moodycamel::ConcurrentQueue<QueueItem> s_queue;

static moodycamel::ProducerToken& GetToken()
{
    static thread_local moodycamel::ProducerToken token( s_queue );
    return token;
}


#ifndef TRACY_DISABLE
Profiler s_profiler;
#endif

static Profiler* s_instance = nullptr;

Profiler::Profiler()
    : m_timeBegin( GetTime() )
    , m_mainThread( GetThreadHandle() )
    , m_shutdown( false )
    , m_id( 0 )
    , m_stream( LZ4_createStream() )
    , m_buffer( new char[TargetFrameSize*3] )
    , m_bufferOffset( 0 )
{
    assert( !s_instance );
    s_instance = this;

    m_thread = std::thread( [this] { Worker(); } );
    SetThreadName( m_thread, "Tracy Profiler" );
}

Profiler::~Profiler()
{
    m_shutdown.store( true, std::memory_order_relaxed );
    m_thread.join();

    delete[] m_buffer;
    LZ4_freeStream( m_stream );

    assert( s_instance );
    s_instance = nullptr;
}

uint64_t Profiler::GetNewId()
{
    return s_instance->m_id.fetch_add( 1, std::memory_order_relaxed );
}

int64_t Profiler::GetTime()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
}

uint64_t Profiler::ZoneBegin( QueueZoneBegin&& data )
{
    auto id = GetNewId();
    QueueItem item;
    item.hdr.type = QueueType::ZoneBegin;
    item.hdr.id = id;
    item.zoneBegin = std::move( data );
    s_queue.enqueue( GetToken(), std::move( item ) );
    return id;
}

void Profiler::ZoneEnd( uint64_t id, QueueZoneEnd&& data )
{
    QueueItem item;
    item.hdr.type = QueueType::ZoneEnd;
    item.hdr.id = id;
    item.zoneEnd = std::move( data );
    s_queue.enqueue( GetToken(), std::move( item ) );
}

void Profiler::FrameMark()
{
    QueueItem item;
    item.hdr.type = QueueType::FrameMark;
    item.hdr.id = (uint64_t)GetTime();
    s_queue.enqueue( GetToken(), std::move( item ) );
}

bool Profiler::ShouldExit()
{
    return s_instance->m_shutdown.load( std::memory_order_relaxed );
}

void Profiler::Worker()
{
    enum { BulkSize = TargetFrameSize / QueueItemSize };

    moodycamel::ConsumerToken token( s_queue );

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

        LZ4_resetStream( m_stream );

        for(;;)
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;

            QueueItem item[BulkSize];
            const auto sz = s_queue.try_dequeue_bulk( token, item, BulkSize );
            if( sz > 0 )
            {
                auto buf = m_buffer + m_bufferOffset;
                auto ptr = buf;
                for( size_t i=0; i<sz; i++ )
                {
                    const auto dsz = QueueDataSize[item[i].hdr.idx];
                    memcpy( ptr, item+i, dsz );
                    ptr += dsz;
                }
                if( !SendData( buf, ptr - buf ) ) break;
                m_bufferOffset += ptr - buf;
                if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;
            }
            else
            {
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }

            while( m_sock->HasData() )
            {
                if( !HandleServerQuery() ) break;
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
    const lz4sz_t lz4sz = LZ4_compress_fast_continue( m_stream, data, lz4 + sizeof( lz4sz_t ), len, LZ4Size, 1 );
    memcpy( lz4, &lz4sz, sizeof( lz4sz ) );
    if( m_sock->Send( lz4, lz4sz + sizeof( lz4sz_t ) ) == -1 ) return false;
#endif
    return true;
}

bool Profiler::SendString( uint64_t str, const char* ptr, QueueType type )
{
    assert( type == QueueType::StringData || type == QueueType::ThreadName );

    QueueHeader hdr;
    hdr.type = type;
    hdr.id = str;

    auto buf = m_buffer + m_bufferOffset;
    memcpy( buf, &hdr, sizeof( hdr ) );

    auto len = strlen( ptr );
    assert( len < TargetFrameSize - sizeof( hdr ) - sizeof( uint16_t ) );
    assert( len <= std::numeric_limits<uint16_t>::max() );
    uint16_t l16 = len;
    memcpy( buf + sizeof( hdr ), &l16, sizeof( l16 ) );
    memcpy( buf + sizeof( hdr ) + sizeof( l16 ), ptr, l16 );

    m_bufferOffset += sizeof( hdr ) + sizeof( l16 ) + l16;
    if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;

    return SendData( buf, sizeof( hdr ) + sizeof( l16 ) + l16 );
}

bool Profiler::HandleServerQuery()
{
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    uint8_t type;
    if( !m_sock->Read( &type, sizeof( type ), &tv, ShouldExit ) ) return false;

    uint64_t ptr;
    if( !m_sock->Read( &ptr, sizeof( ptr ), &tv, ShouldExit ) ) return false;

    switch( type )
    {
    case ServerQueryString:
        SendString( ptr, (const char*)ptr, QueueType::StringData );
        break;
    case ServerQueryThreadString:
        if( ptr == m_mainThread )
        {
            SendString( ptr, "Main thread", QueueType::ThreadName );
        }
        else
        {
            SendString( ptr, GetThreadName( ptr ), QueueType::ThreadName );
        }
        break;
    default:
        assert( false );
        break;
    }

    return true;
}

}
