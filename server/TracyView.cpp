#ifdef _MSC_VER
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

#include <algorithm>
#include <assert.h>

#include "../common/tracy_lz4.hpp"
#include "../common/TracyProtocol.hpp"
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
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    for(;;)
    {
        if( m_shutdown.load( std::memory_order_relaxed ) ) return;
        if( !m_sock.Connect( m_addr.c_str(), "8086" ) ) continue;

        uint8_t lz4;

        if( !m_sock.Read( &m_timeBegin, sizeof( m_timeBegin ), &tv, ShouldExit ) ) goto close;
        if( !m_sock.Read( &lz4, sizeof( lz4 ), &tv, ShouldExit ) ) goto close;

        for(;;)
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;

            if( lz4 )
            {
                char buf[TargetFrameSize];
                char lz4buf[LZ4Size];
                lz4sz_t lz4sz;
                if( !m_sock.Read( &lz4sz, sizeof( lz4sz ), &tv, ShouldExit ) ) goto close;
                if( !m_sock.Read( lz4buf, lz4sz, &tv, ShouldExit ) ) goto close;

                auto sz = LZ4_decompress_safe( lz4buf, buf, lz4sz, TargetFrameSize );
                assert( sz >= 0 );

                const char* ptr = buf;
                const char* end = buf + sz;
                while( ptr < end )
                {
                    auto ev = (QueueItem*)ptr;
                    DispatchProcess( *ev, ptr );
                }
            }
            else
            {
                QueueItem ev;
                if( !m_sock.Read( &ev.hdr, sizeof( QueueHeader ), &tv, ShouldExit ) ) goto close;
                const auto payload = QueueDataSize[ev.hdr.idx] - sizeof( QueueHeader );
                if( payload > 0 )
                {
                    if( !m_sock.Read( ((char*)&ev) + sizeof( QueueHeader ), payload, &tv, ShouldExit ) ) goto close;
                }
                DispatchProcess( ev );
            }
        }

close:
        m_sock.Close();
    }
}

void View::DispatchProcess( const QueueItem& ev )
{
    if( ev.hdr.type == QueueType::StringData )
    {
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000;

        char buf[TargetFrameSize];
        uint16_t sz;
        m_sock.Read( &sz, sizeof( sz ), &tv, ShouldExit );
        m_sock.Read( buf, sz, &tv, ShouldExit );
        AddString( ev.hdr.id, std::string( buf, buf+sz ) );
    }
    else
    {
        Process( ev );
    }
}

void View::DispatchProcess( const QueueItem& ev, const char*& ptr )
{
    ptr += QueueDataSize[ev.hdr.idx];
    if( ev.hdr.type == QueueType::StringData )
    {
        uint16_t sz;
        memcpy( &sz, ptr, sizeof( sz ) );
        ptr += sizeof( sz );
        AddString( ev.hdr.id, std::string( ptr, ptr+sz ) );
        ptr += sz;
    }
    else
    {
        Process( ev );
    }
}

void View::Process( const QueueItem& ev )
{
    switch( ev.hdr.type )
    {
    case QueueType::ZoneBegin:
        ProcessZoneBegin( ev.hdr.id, ev.zoneBegin );
        break;
    case QueueType::ZoneEnd:
        ProcessZoneEnd( ev.hdr.id, ev.zoneEnd );
        break;
    default:
        assert( false );
        break;
    }
}

void View::ProcessZoneBegin( uint64_t id, const QueueZoneBegin& ev )
{
    auto it = m_pendingEndZone.find( id );
    const auto idx = m_data.size();
    CheckString( ev.filename );
    CheckString( ev.function );
    std::unique_lock<std::mutex> lock( m_lock );
    if( it == m_pendingEndZone.end() )
    {
        m_data.emplace_back( Event { ev.time, -1 } );
        NewZone( idx );
        lock.unlock();
        m_openZones.emplace( id, idx );
    }
    else
    {
        assert( ev.time <= it->second.time );
        m_data.emplace_back( Event { ev.time, it->second.time } );
        NewZone( idx );
        lock.unlock();
        m_pendingEndZone.erase( it );
    }
}

void View::ProcessZoneEnd( uint64_t id, const QueueZoneEnd& ev )
{
    auto it = m_openZones.find( id );
    if( it == m_openZones.end() )
    {
        m_pendingEndZone.emplace( id, ev );
    }
    else
    {
        const auto idx = it->second;
        std::unique_lock<std::mutex> lock( m_lock );
        assert( ev.time >= m_data[idx].start );
        m_data[idx].end = ev.time;
        UpdateZone( idx );
        lock.unlock();
        m_openZones.erase( it );
    }
}

void View::CheckString( uint64_t ptr )
{
    if( m_strings.find( ptr ) != m_strings.end() ) return;
    if( m_pendingStrings.find( ptr ) != m_pendingStrings.end() ) return;

    m_pendingStrings.emplace( ptr );
    m_sock.Send( &ptr, sizeof( ptr ) );
}

void View::AddString( uint64_t ptr, std::string&& str )
{
    assert( m_strings.find( ptr ) == m_strings.end( ptr ) );
    auto it = m_pendingStrings.find( ptr );
    assert( it != m_pendingStrings.end() );
    m_pendingStrings.erase( it );
    std::lock_guard<std::mutex> lock( m_lock );
    m_strings.emplace( ptr, std::move( str ) );
}

void View::NewZone( uint64_t idx )
{
    if( !m_timeline.empty() )
    {
        auto& zone = m_data[idx];
        const auto lastend = m_data[m_timeline.back()].end;
        if( lastend != -1 && lastend < zone.start )
        {
            m_timeline.emplace_back( idx );
        }
        else
        {

        }
    }
    else
    {
        m_timeline.emplace_back( idx );
    }
}

void View::UpdateZone( uint64_t idx )
{
    auto& zone = m_data[idx++];
    assert( zone.end != -1 );
}

}
