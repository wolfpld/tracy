#ifdef _MSC_VER
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

#include <algorithm>
#include <assert.h>
#include <inttypes.h>
#include <limits>
#include <stdlib.h>

#include "../common/TracyProtocol.hpp"
#include "../common/TracySystem.hpp"
#include "../common/TracyQueue.hpp"
#include "TracyFileRead.hpp"
#include "TracyFileWrite.hpp"
#include "TracyImGui.hpp"
#include "TracyView.hpp"

#ifdef TRACY_FILESELECTOR
#  include "../nfd/nfd.h"
#endif

namespace tracy
{

static TextData* GetTextData( Event& zone )
{
    if( !zone.text ) zone.text = new TextData {};
    return zone.text;
}

static View* s_instance = nullptr;

View::View( const char* addr )
    : m_addr( addr )
    , m_shutdown( false )
    , m_connected( false )
    , m_hasData( false )
    , m_staticView( false )
    , m_zonesCnt( 0 )
    , m_mbps( 64 )
    , m_stream( LZ4_createStreamDecode() )
    , m_buffer( new char[TargetFrameSize*3] )
    , m_bufferOffset( 0 )
    , m_frameScale( 0 )
    , m_pause( false )
    , m_frameStart( 0 )
    , m_zvStart( 0 )
    , m_zvEnd( 0 )
    , m_zoneInfoWindow( nullptr )
{
    assert( s_instance == nullptr );
    s_instance = this;

    ImGuiStyle& style = ImGui::GetStyle();
    style.FrameRounding = 2.f;

    m_thread = std::thread( [this] { Worker(); } );
    SetThreadName( m_thread, "Tracy View" );
}

View::View( FileRead& f )
    : m_shutdown( false )
    , m_connected( false )
    , m_hasData( true )
    , m_staticView( true )
    , m_zonesCnt( 0 )
    , m_stream( nullptr )
    , m_buffer( nullptr )
    , m_frameScale( 0 )
    , m_pause( false )
    , m_frameStart( 0 )
    , m_zvStart( 0 )
    , m_zvEnd( 0 )
    , m_zoneInfoWindow( nullptr )
{
    assert( s_instance == nullptr );
    s_instance = this;

    f.Read( &m_delay, sizeof( m_delay ) );
    f.Read( &m_resolution, sizeof( m_resolution ) );
    f.Read( &m_timerMul, sizeof( m_timerMul ) );

    uint64_t sz;
    f.Read( &sz, sizeof( sz ) );
    m_frames.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t v;
        f.Read( &v, sizeof( v ) );
        m_frames.push_back( v );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( &ptr, sizeof( ptr ) );
        uint64_t ssz;
        f.Read( &ssz, sizeof( ssz ) );
        char tmp[16*1024];
        f.Read( tmp, ssz );
        m_strings.emplace( ptr, std::string( tmp, tmp+ssz ) );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( &ptr, sizeof( ptr ) );
        uint64_t ssz;
        f.Read( &ssz, sizeof( ssz ) );
        char tmp[16*1024];
        f.Read( tmp, ssz );
        m_threadNames.emplace( ptr, std::string( tmp, tmp+ssz ) );
    }

    std::unordered_map<uint64_t, const char*> stringMap;

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( &ptr, sizeof( ptr ) );
        uint64_t ssz;
        f.Read( &ssz, sizeof( ssz ) );
        auto dst = new char[ssz+1];
        f.Read( dst, ssz );
        dst[ssz] = '\0';
        m_customStrings.emplace( dst );
        stringMap.emplace( ptr, dst );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( &ptr, sizeof( ptr ) );
        QueueSourceLocation srcloc;
        f.Read( &srcloc, sizeof( srcloc ) );
        m_sourceLocation.emplace( ptr, srcloc );
    }

    f.Read( &sz, sizeof( sz ) );
    m_threads.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto td = new ThreadData;
        f.Read( &td->id, sizeof( td->id ) );
        ReadTimeline( f, td->timeline, nullptr, stringMap );
        m_threads.push_back( td );
    }
}

View::~View()
{
    m_shutdown.store( true, std::memory_order_relaxed );
    if( !m_staticView )
    {
        m_thread.join();
    }

    delete[] m_buffer;
    LZ4_freeStreamDecode( m_stream );

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

        std::chrono::time_point<std::chrono::high_resolution_clock> t0;

        uint8_t lz4;
        uint64_t bytes = 0;

        {
            WelcomeMessage welcome;
            if( !m_sock.Read( &welcome, sizeof( welcome ), &tv, ShouldExit ) ) goto close;
            lz4 = welcome.lz4;
            m_timerMul = welcome.timerMul;
            m_frames.push_back( welcome.timeBegin * m_timerMul );
            m_delay = welcome.delay * m_timerMul;
            m_resolution = welcome.resolution * m_timerMul;
        }

        m_hasData.store( true, std::memory_order_release );

        LZ4_setStreamDecode( m_stream, nullptr, 0 );
        m_connected.store( true, std::memory_order_relaxed );

        t0 = std::chrono::high_resolution_clock::now();

        for(;;)
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;

            if( lz4 )
            {
                auto buf = m_buffer + m_bufferOffset;
                char lz4buf[LZ4Size];
                lz4sz_t lz4sz;
                if( !m_sock.Read( &lz4sz, sizeof( lz4sz ), &tv, ShouldExit ) ) goto close;
                if( !m_sock.Read( lz4buf, lz4sz, &tv, ShouldExit ) ) goto close;
                bytes += sizeof( lz4sz ) + lz4sz;

                auto sz = LZ4_decompress_safe_continue( m_stream, lz4buf, buf, lz4sz, TargetFrameSize );
                assert( sz >= 0 );

                const char* ptr = buf;
                const char* end = buf + sz;
                while( ptr < end )
                {
                    auto ev = (QueueItem*)ptr;
                    DispatchProcess( *ev, ptr );
                }

                m_bufferOffset += sz;
                if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;
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
                bytes += sizeof( QueueHeader ) + payload;   // ignores string transfer
                DispatchProcess( ev );
            }

            auto t1 = std::chrono::high_resolution_clock::now();
            auto td = std::chrono::duration_cast<std::chrono::milliseconds>( t1 - t0 ).count();
            enum { MbpsUpdateTime = 200 };
            if( td > MbpsUpdateTime )
            {
                std::lock_guard<std::mutex> lock( m_mbpslock );
                m_mbps.erase( m_mbps.begin() );
                m_mbps.emplace_back( bytes / ( td * 125.f ) );
                t0 = t1;
                bytes = 0;
            }
        }

close:
        m_sock.Close();
        m_connected.store( false, std::memory_order_relaxed );
    }
}

void View::DispatchProcess( const QueueItem& ev )
{
    if( ev.hdr.type == QueueType::CustomStringData || ev.hdr.type == QueueType::StringData || ev.hdr.type == QueueType::ThreadName )
    {
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000;

        char buf[TargetFrameSize];
        uint16_t sz;
        m_sock.Read( &sz, sizeof( sz ), &tv, ShouldExit );
        m_sock.Read( buf, sz, &tv, ShouldExit );
        if( ev.hdr.type == QueueType::CustomStringData )
        {
            AddCustomString( ev.hdr.id, std::string( buf, buf+sz ) );
        }
        else if( ev.hdr.type == QueueType::StringData )
        {
            AddString( ev.hdr.id, std::string( buf, buf+sz ) );
        }
        else
        {
            AddThreadString( ev.hdr.id, std::string( buf, buf+sz ) );
        }
    }
    else
    {
        Process( ev );
    }
}

void View::DispatchProcess( const QueueItem& ev, const char*& ptr )
{
    ptr += QueueDataSize[ev.hdr.idx];
    if( ev.hdr.type == QueueType::CustomStringData || ev.hdr.type == QueueType::StringData || ev.hdr.type == QueueType::ThreadName )
    {
        uint16_t sz;
        memcpy( &sz, ptr, sizeof( sz ) );
        ptr += sizeof( sz );
        if( ev.hdr.type == QueueType::CustomStringData )
        {
            AddCustomString( ev.hdr.id, std::string( ptr, ptr+sz ) );
        }
        else if( ev.hdr.type == QueueType::StringData )
        {
            AddString( ev.hdr.id, std::string( ptr, ptr+sz ) );
        }
        else
        {
            AddThreadString( ev.hdr.id, std::string( ptr, ptr+sz ) );
        }
        ptr += sz;
    }
    else
    {
        Process( ev );
    }
}

void View::ServerQuery( uint8_t type, uint64_t data )
{
    enum { DataSize = sizeof( type ) + sizeof( data ) };
    char tmp[DataSize];
    memcpy( tmp, &type, sizeof( type ) );
    memcpy( tmp + sizeof( type ), &data, sizeof( data ) );
    m_sock.Send( tmp, DataSize );
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
    case QueueType::FrameMarkMsg:
        ProcessFrameMark( ev.hdr.id );
        break;
    case QueueType::SourceLocation:
        AddSourceLocation( ev.hdr.id, ev.srcloc );
        break;
    case QueueType::ZoneText:
        ProcessZoneText( ev.hdr.id, ev.zoneText );
        break;
    case QueueType::ZoneName:
        ProcessZoneName( ev.hdr.id, ev.zoneName );
        break;
    default:
        assert( false );
        break;
    }
}

void View::ProcessZoneBegin( uint64_t id, const QueueZoneBegin& ev )
{
    auto it = m_pendingEndZone.find( id );
    auto zone = m_slab.Alloc<Event>();

    CheckSourceLocation( ev.srcloc );
    CheckThreadString( ev.thread );

    zone->start = ev.time * m_timerMul;
    zone->srcloc = ev.srcloc;
    zone->text = nullptr;

    std::unique_lock<std::mutex> lock( m_lock );

    if( it == m_pendingEndZone.end() )
    {
        zone->end = -1;
        NewZone( zone, ev.thread );
        lock.unlock();
        m_openZones.emplace( id, zone );
    }
    else
    {
        zone->end = it->second.time * m_timerMul;
        assert( zone->start <= zone->end );
        NewZone( zone, ev.thread );
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
        auto zone = it->second;
        std::unique_lock<std::mutex> lock( m_lock );
        assert( zone->end == -1 );
        zone->end = ev.time * m_timerMul;
        assert( zone->end >= zone->start );
        UpdateZone( zone );
        lock.unlock();
        m_openZones.erase( it );
    }
}

void View::ProcessFrameMark( uint64_t id )
{
    assert( !m_frames.empty() );
    const auto lastframe = m_frames.back();
    const auto time = id * m_timerMul;
    if( lastframe < time )
    {
        std::unique_lock<std::mutex> lock( m_lock );
        m_frames.push_back( time );
    }
    else
    {
        auto it = std::lower_bound( m_frames.begin(), m_frames.end(), time );
        std::unique_lock<std::mutex> lock( m_lock );
        m_frames.insert( it, time );
    }
}

void View::ProcessZoneText( uint64_t id, const QueueZoneText& ev )
{
    auto it = m_openZones.find( id );
    assert( it != m_openZones.end() );
    CheckCustomString( ev.text, it->second );
}

void View::ProcessZoneName( uint64_t id, const QueueZoneName& ev )
{
    auto it = m_openZones.find( id );
    assert( it != m_openZones.end() );
    CheckString( ev.name );
    GetTextData( *it->second )->zoneName = ev.name;
}

void View::CheckString( uint64_t ptr )
{
    if( m_strings.find( ptr ) != m_strings.end() ) return;
    if( m_pendingStrings.find( ptr ) != m_pendingStrings.end() ) return;

    m_pendingStrings.emplace( ptr );

    ServerQuery( ServerQueryString, ptr );
}

void View::CheckThreadString( uint64_t id )
{
    if( m_threadNames.find( id ) != m_threadNames.end() ) return;
    if( m_pendingThreads.find( id ) != m_pendingThreads.end() ) return;

    m_pendingThreads.emplace( id );

    ServerQuery( ServerQueryThreadString, id );
}

void View::CheckCustomString( uint64_t ptr, Event* dst )
{
    assert( m_pendingCustomStrings.find( ptr ) == m_pendingCustomStrings.end() );
    m_pendingCustomStrings.emplace( ptr, dst );

    ServerQuery( ServerQueryCustomString, ptr );
}

void View::CheckSourceLocation( uint64_t ptr )
{
    if( m_sourceLocation.find( ptr ) != m_sourceLocation.end() ) return;
    if( m_pendingSourceLocation.find( ptr ) != m_pendingSourceLocation.end() ) return;

    m_pendingSourceLocation.emplace( ptr );

    ServerQuery( ServerQuerySourceLocation, ptr );
}

void View::AddString( uint64_t ptr, std::string&& str )
{
    assert( m_strings.find( ptr ) == m_strings.end() );
    auto it = m_pendingStrings.find( ptr );
    assert( it != m_pendingStrings.end() );
    m_pendingStrings.erase( it );
    std::lock_guard<std::mutex> lock( m_lock );
    m_strings.emplace( ptr, std::move( str ) );
}

void View::AddThreadString( uint64_t id, std::string&& str )
{
    assert( m_threadNames.find( id ) == m_threadNames.end() );
    auto it = m_pendingThreads.find( id );
    assert( it != m_pendingThreads.end() );
    m_pendingThreads.erase( it );
    std::lock_guard<std::mutex> lock( m_lock );
    m_threadNames.emplace( id, std::move( str ) );
}

void View::AddCustomString( uint64_t ptr, std::string&& str )
{
    auto pit = m_pendingCustomStrings.find( ptr );
    assert( pit != m_pendingCustomStrings.end() );
    auto sit = m_customStrings.find( str.c_str() );
    if( sit == m_customStrings.end() )
    {
        const auto sz = str.size();
        auto ptr = new char[sz+1];
        memcpy( ptr, str.c_str(), sz );
        ptr[sz] = '\0';
        GetTextData( *pit->second )->userText = ptr;
        m_customStrings.emplace( ptr );
    }
    else
    {
        GetTextData( *pit->second )->userText = *sit;
    }
    m_pendingCustomStrings.erase( pit );
}

void View::AddSourceLocation( uint64_t ptr, const QueueSourceLocation& srcloc )
{
    assert( m_sourceLocation.find( ptr ) == m_sourceLocation.end() );
    auto it = m_pendingSourceLocation.find( ptr );
    assert( it != m_pendingSourceLocation.end() );
    m_pendingSourceLocation.erase( it );
    CheckString( srcloc.file );
    CheckString( srcloc.function );
    std::lock_guard<std::mutex> lock( m_lock );
    m_sourceLocation.emplace( ptr, srcloc );
}

void View::NewZone( Event* zone, uint64_t thread )
{
    m_zonesCnt++;
    Vector<Event*>* timeline;
    auto it = m_threadMap.find( thread );
    if( it == m_threadMap.end() )
    {
        m_threadMap.emplace( thread, (uint32_t)m_threads.size() );
        m_threads.push_back( new ThreadData { thread } );
        timeline = &m_threads.back()->timeline;
    }
    else
    {
        timeline = &m_threads[it->second]->timeline;
    }

    InsertZone( zone, nullptr, *timeline );
}

void View::UpdateZone( Event* zone )
{
    assert( zone->end != -1 );
    auto it = std::upper_bound( zone->child.begin(), zone->child.end(), zone->end, [] ( const auto& l, const auto& r ) { return l < r->start; } );
    if( it == zone->child.end() ) return;

    // here be dragons
    auto& pvec = GetParentVector( *zone );
    auto pit = std::lower_bound( pvec.begin(), pvec.end(), zone->start, [] ( const auto& l, const auto& r ) { return l->start < r; } );
    assert( *pit == zone );
    ++pit;
    for( auto eit = it; eit != zone->child.end(); ++eit )
    {
        (*eit)->parent = zone->parent;
        pit = pvec.insert( pit, *eit );
        ++pit;
    }
    zone->child.erase( it, zone->child.end() );
}

void View::InsertZone( Event* zone, Event* parent, Vector<Event*>& vec )
{
    if( !vec.empty() )
    {
        const auto lastend = vec.back()->end;
        if( lastend != -1 && lastend <= zone->start )
        {
            zone->parent = parent;
            vec.push_back( zone );
        }
        else
        {
            auto it = std::upper_bound( vec.begin(), vec.end(), zone->start, [] ( const auto& l, const auto& r ) { return l < r->start; } );
            if( it == vec.end() )
            {
                assert( vec.back()->end == -1 || vec.back()->end >= zone->end );
                InsertZone( zone, vec.back(), vec.back()->child );
            }
            else
            {
                zone->parent = parent;

                if( zone->end == -1 )
                {
                    for( auto zit = it; zit != vec.end(); ++zit )
                    {
                        (*zit)->parent = zone;
                        zone->child.push_back( *zit );
                    }
                    vec.erase( it, vec.end() );
                    vec.push_back( zone );
                }
                else
                {
                    auto eit = std::lower_bound( it, vec.end(), zone->end, [] ( const auto& l, const auto& r ) { return l->start < r; } );
                    for( auto zit = it; zit != eit; zit++ )
                    {
                        (*zit)->parent = zone;
                        zone->child.push_back( *zit );
                    }
                    auto nit = vec.erase( it, eit );
                    vec.insert( nit, zone );
                }
            }
        }
    }
    else
    {
        zone->parent = parent;
        vec.push_back( zone );
    }
}

uint64_t View::GetFrameTime( size_t idx ) const
{
    if( idx < m_frames.size() - 1 )
    {
        return m_frames[idx+1] - m_frames[idx];
    }
    else
    {
        const auto last = GetLastTime();
        return last == 0 ? 0 : last - m_frames.back();
    }
}

uint64_t View::GetFrameBegin( size_t idx ) const
{
    assert( idx < m_frames.size() );
    return m_frames[idx];
}

uint64_t View::GetFrameEnd( size_t idx ) const
{
    if( idx < m_frames.size() - 1 )
    {
        return m_frames[idx+1];
    }
    else
    {
        return GetLastTime();
    }
}

uint64_t View::GetLastTime() const
{
    uint64_t last = 0;
    if( !m_frames.empty() ) last = m_frames.back();
    for( auto& v : m_threads )
    {
        if( !v->timeline.empty() )
        {
            auto ev = v->timeline.back();
            if( ev->end == -1 )
            {
                if( ev->start > last ) last = ev->start;
            }
            else if( ev->end > last )
            {
                last = ev->end;
            }
        }
    }
    return last;
}

int64_t View::GetZoneEnd( const Event& ev ) const
{
    auto ptr = &ev;
    for(;;)
    {
        if( ptr->end != -1 ) return ptr->end;
        if( ptr->child.empty() ) return ptr->start;
        ptr = ptr->child.back();
    }
}

Vector<Event*>& View::GetParentVector( const Event& ev )
{
    if( ev.parent )
    {
        return ev.parent->child;
    }
    else
    {
        for( auto& t : m_threads )
        {
            auto it = std::lower_bound( t->timeline.begin(), t->timeline.end(), ev.start, [] ( const auto& l, const auto& r ) { return l->start < r; } );
            if( it != t->timeline.end() && *it == &ev ) return t->timeline;
        }
        assert( false );
        static Vector<Event*> empty;
        return empty;
    }
}

const char* View::TimeToString( int64_t ns ) const
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    const char* sign = "";
    if( ns < 0 )
    {
        sign = "-";
        ns = -ns;
    }

    if( ns < 1000 )
    {
        sprintf( buf, "%s%" PRIu64 " ns", sign, ns );
    }
    else if( ns < 1000ull * 1000 )
    {
        sprintf( buf, "%s%.2f us", sign, ns / 1000. );
    }
    else if( ns < 1000ull * 1000 * 1000 )
    {
        sprintf( buf, "%s%.2f ms", sign, ns / ( 1000. * 1000. ) );
    }
    else if( ns < 1000ull * 1000 * 1000 * 60 )
    {
        sprintf( buf, "%s%.2f s", sign, ns / ( 1000. * 1000. * 1000. ) );
    }
    else
    {
        const auto m = ns / ( 1000ull * 1000 * 1000 * 60 );
        const auto s = ns - m * ( 1000ull * 1000 * 1000 * 60 );
        sprintf( buf, "%s%" PRIu64 ":%04.1f", sign, m, s / ( 1000. * 1000. * 1000. ) );
    }
    return buf;
}

const char* View::GetString( uint64_t ptr ) const
{
    const auto it = m_strings.find( ptr );
    if( it == m_strings.end() )
    {
        return "???";
    }
    else
    {
        return it->second.c_str();
    }
}

const char* View::GetThreadString( uint64_t id ) const
{
    const auto it = m_threadNames.find( id );
    if( it == m_threadNames.end() )
    {
        return "???";
    }
    else
    {
        return it->second.c_str();
    }
}

const QueueSourceLocation& View::GetSourceLocation( uint64_t srcloc ) const
{
    static const QueueSourceLocation empty = {};
    const auto it = m_sourceLocation.find( srcloc );
    if( it == m_sourceLocation.end() ) return empty;
    return it->second;
}

void View::Draw()
{
    s_instance->DrawImpl();
}

void View::DrawImpl()
{
    if( !m_hasData.load( std::memory_order_acquire ) )
    {
        ImGui::Begin( m_addr.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_ShowBorders );
        ImGui::Text( "Waiting for connection..." );
        ImGui::End();
        return;
    }

    if( !m_staticView )
    {
        DrawConnection();
    }

    std::lock_guard<std::mutex> lock( m_lock );
    ImGui::Begin( "Profiler", nullptr, ImGuiWindowFlags_ShowBorders );
    if( ImGui::Button( m_pause ? "Resume" : "Pause", ImVec2( 80, 0 ) ) ) m_pause = !m_pause;
    ImGui::SameLine();
    ImGui::Text( "Frames: %-7" PRIu64 " Time span: %-10s View span: %-10s Zones: %-10" PRIu64" Queue delay: %s  Timer resolution: %s", m_frames.size(), TimeToString( GetLastTime() - m_frames[0] ), TimeToString( m_zvEnd - m_zvStart ), m_zonesCnt, TimeToString( m_delay ), TimeToString( m_resolution ) );
    DrawFrames();
    DrawZones();
    ImGui::End();

    m_zoneHighlight = nullptr;
    DrawZoneInfoWindow();

    if( m_zvStartNext != 0 )
    {
        m_zvStart = m_zvStartNext;
        m_zvEnd = m_zvEndNext;
        m_pause = true;
    }
}

void View::DrawConnection()
{
    ImGui::Begin( m_addr.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_ShowBorders );
    {
        std::lock_guard<std::mutex> lock( m_mbpslock );
        const auto mbps = m_mbps.back();
        char buf[64];
        if( mbps < 0.1f )
        {
            sprintf( buf, "%6.2f Kbps", mbps * 1000.f );
        }
        else
        {
            sprintf( buf, "%6.2f Mbps", mbps );
        }
        ImGui::Dummy( ImVec2( 10, 0 ) );
        ImGui::SameLine();
        ImGui::PlotLines( buf, m_mbps.data(), m_mbps.size(), 0, nullptr, 0, std::numeric_limits<float>::max(), ImVec2( 150, 0 ) );
    }

    ImGui::Text( "Memory usage: %.2f MB", memUsage.load( std::memory_order_relaxed ) / ( 1024.f * 1024.f ) );

    const auto wpos = ImGui::GetWindowPos() + ImGui::GetWindowContentRegionMin();
    ImGui::GetWindowDrawList()->AddCircleFilled( wpos + ImVec2( 6, 9 ), 5.f, m_connected.load( std::memory_order_relaxed ) ? 0xFF2222CC : 0xFF444444, 10 );

    std::lock_guard<std::mutex> lock( m_lock );
    {
        const auto sz = m_frames.size();
        if( sz > 1 )
        {
            const auto dt = m_frames[sz-1] - m_frames[sz-2];
            const auto dtm = dt / 1000000.f;
            const auto fps = 1000.f / dtm;
            ImGui::Text( "FPS: %6.1f  Frame time: %.2f ms", fps, dtm );
        }
    }

    if( ImGui::Button( "Save trace" ) )
    {
#ifdef TRACY_FILESELECTOR
        nfdchar_t* fn;
        auto res = NFD_SaveDialog( "tracy", nullptr, &fn );
        if( res == NFD_OKAY )
#else
        const char* fn = "trace.tracy";
#endif
        {
            auto f = std::unique_ptr<FileWrite>( FileWrite::Open( fn ) );
            if( f )
            {
                Write( *f );
            }
        }
    }

    ImGui::End();
}

static ImU32 GetFrameColor( uint64_t frameTime )
{
    enum { BestTime = 1000 * 1000 * 1000 / 143 };
    enum { GoodTime = 1000 * 1000 * 1000 / 59 };
    enum { BadTime = 1000 * 1000 * 1000 / 29 };

    return frameTime > BadTime  ? 0xFF2222DD :
           frameTime > GoodTime ? 0xFF22DDDD :
           frameTime > BestTime ? 0xFF22DD22 : 0xFFDD9900;
}

static int GetFrameWidth( int frameScale )
{
    return frameScale == 0 ? 4 : ( frameScale == -1 ? 6 : 1 );
}

static int GetFrameGroup( int frameScale )
{
    return frameScale < 2 ? 1 : ( 1 << ( frameScale - 1 ) );
}

void View::DrawFrames()
{
    assert( !m_frames.empty() );

    enum { Height = 40 };
    enum { MaxFrameTime = 50 * 1000 * 1000 };  // 50ms

    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if( window->SkipItems ) return;

    auto& io = ImGui::GetIO();

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto wspace = ImGui::GetWindowContentRegionMax() - ImGui::GetWindowContentRegionMin();
    const auto w = wspace.x;
    auto draw = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton( "##frames", ImVec2( w, Height ) );
    bool hover = ImGui::IsItemHovered();

    draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x33FFFFFF );
    const auto wheel = io.MouseWheel;
    const auto prevScale = m_frameScale;
    if( hover )
    {
        if( wheel > 0 )
        {
            if( m_frameScale > -1 ) m_frameScale--;
        }
        else if( wheel < 0 )
        {
            if( m_frameScale < 10 ) m_frameScale++;
        }
    }

    const int fwidth = GetFrameWidth( m_frameScale );
    const int group = GetFrameGroup( m_frameScale );
    const int total = m_frames.size();
    const int onScreen = ( w - 2 ) / fwidth;
    if( !m_pause )
    {
        m_frameStart = ( total < onScreen * group ) ? 0 : total - onScreen * group;
        m_zvStart = m_frames[std::max( 0, (int)m_frames.size() - 4 )];
        if( m_frames.size() == 1 )
        {
            m_zvEnd = GetLastTime();
        }
        else
        {
            m_zvEnd = m_frames.back();
        }
    }

    if( hover )
    {
        if( ImGui::IsMouseDragging( 1, 0 ) )
        {
            m_pause = true;
            const auto delta = ImGui::GetMouseDragDelta( 1, 0 ).x;
            if( abs( delta ) >= fwidth )
            {
                const auto d = (int)delta / fwidth;
                m_frameStart = std::max( 0, m_frameStart - d * group );
                io.MouseClickedPos[1].x = io.MousePos.x + d * fwidth - delta;
            }
        }

        const auto mx = io.MousePos.x;
        if( mx > wpos.x && mx < wpos.x + w - 1 )
        {
            const auto mo = mx - ( wpos.x + 1 );
            const auto off = mo * group / fwidth;

            const int sel = m_frameStart + off;
            if( sel < total )
            {
                ImGui::BeginTooltip();
                if( group > 1 )
                {
                    uint64_t f = GetFrameTime( sel );
                    auto g = std::min( group, total - sel );
                    for( int j=1; j<g; j++ )
                    {
                        f = std::max( f, GetFrameTime( sel + j ) );
                    }

                    ImGui::Text( "Frames: %i - %i (%i)", sel, sel + g - 1, g );
                    ImGui::Text( "Max frame time: %s", TimeToString( f ) );
                }
                else
                {
                    ImGui::Text( "Frame: %i", sel );
                    ImGui::Text( "Frame time: %s", TimeToString( GetFrameTime( sel ) ) );
                }
                ImGui::Text( "Time from start of program: %s", TimeToString( m_frames[sel] - m_frames[0] ) );
                ImGui::EndTooltip();

                if( ImGui::IsMouseClicked( 0 ) )
                {
                    m_pause = true;
                    m_zvStart = GetFrameBegin( sel );
                    m_zvEnd = GetFrameEnd( sel + group - 1 );
                    if( m_zvStart == m_zvEnd ) m_zvStart--;
                }
                else if( ImGui::IsMouseDragging( 0 ) )
                {
                    m_zvStart = std::min( m_zvStart, (int64_t)GetFrameBegin( sel ) );
                    m_zvEnd = std::max( m_zvEnd, (int64_t)GetFrameEnd( sel + group - 1 ) );
                }
            }

            if( m_pause && wheel != 0 )
            {
                const int pfwidth = GetFrameWidth( prevScale );
                const int pgroup = GetFrameGroup( prevScale );

                const auto oldoff = mo * pgroup / pfwidth;
                m_frameStart = std::min( total, std::max( 0, m_frameStart - int( off - oldoff ) ) );
            }
        }
    }

    int i = 0, idx = 0;
    while( i < onScreen && m_frameStart + idx < total )
    {
        uint64_t f = GetFrameTime( m_frameStart + idx );
        int g;
        if( group > 1 )
        {
            g = std::min( group, total - ( m_frameStart + idx ) );
            for( int j=1; j<g; j++ )
            {
                f = std::max( f, GetFrameTime( m_frameStart + idx + j ) );
            }
        }

        const auto h = float( std::min<uint64_t>( MaxFrameTime, f ) ) / MaxFrameTime * ( Height - 2 );
        if( fwidth != 1 )
        {
            draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), GetFrameColor( f ) );
        }
        else
        {
            draw->AddLine( wpos + ImVec2( 1+i, Height-2-h ), wpos + ImVec2( 1+i, Height-2 ), GetFrameColor( f ) );
        }

        i++;
        idx += group;
    }

    const auto zitbegin = std::lower_bound( m_frames.begin(), m_frames.end(), m_zvStart );
    if( zitbegin == m_frames.end() ) return;
    const auto zitend = std::lower_bound( m_frames.begin(), m_frames.end(), m_zvEnd );

    auto zbegin = (int)std::distance( m_frames.begin(), zitbegin );
    if( zbegin > 0 && *zitbegin != m_zvStart ) zbegin--;
    const auto zend = (int)std::distance( m_frames.begin(), zitend );

    if( zend > m_frameStart && zbegin < m_frameStart + onScreen * group )
    {
        auto x0 = std::max( 0, ( zbegin - m_frameStart ) * fwidth / group );
        auto x1 = std::min( onScreen * fwidth, ( zend - m_frameStart ) * fwidth / group );

        if( x0 == x1 ) x1 = x0 + 1;

        draw->AddRectFilled( wpos + ImVec2( 1+x0, 0 ), wpos + ImVec2( 1+x1, Height ), 0x55DD22DD );
    }
}

struct TimeScale
{
    uint64_t div;
    const char* fmt;
};

void View::DrawZones()
{
    if( m_zvStart == m_zvEnd ) return;
    assert( m_zvStart < m_zvEnd );

    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if( window->SkipItems ) return;

    auto& io = ImGui::GetIO();

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto w = ImGui::GetWindowContentRegionWidth();
    const auto h = ImGui::GetContentRegionAvail().y;
    auto draw = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton( "##zones", ImVec2( w, h ) );
    bool hover = ImGui::IsItemHovered();

    auto timespan = m_zvEnd - m_zvStart;
    auto pxns = w / double( timespan );

    if( hover )
    {
        if( ImGui::IsMouseDragging( 1, 0 ) )
        {
            m_pause = true;
            const auto delta = ImGui::GetMouseDragDelta( 1, 0 ).x;
            const auto nspx = double( timespan ) / w;
            const auto dpx = int64_t( delta * nspx );
            if( dpx != 0 )
            {
                m_zvStart -= dpx;
                m_zvEnd -= dpx;
                io.MouseClickedPos[1].x = io.MousePos.x;
            }
        }

        const auto wheel = io.MouseWheel;
        if( wheel != 0 )
        {
            m_pause = true;
            const double mouse = io.MousePos.x - wpos.x;
            const auto p = mouse / w;
            const auto p1 = timespan * p;
            const auto p2 = timespan - p1;
            if( wheel > 0 )
            {
                m_zvStart += int64_t( p1 * 0.2f );
                m_zvEnd -= int64_t( p2 * 0.2f );
            }
            else if( timespan < 1000ull * 1000 * 1000 * 60 )
            {
                m_zvStart -= std::max( int64_t( 1 ), int64_t( p1 * 0.2f ) );
                m_zvEnd += std::max( int64_t( 1 ), int64_t( p2 * 0.2f ) );
            }
            timespan = m_zvEnd - m_zvStart;
            pxns = w / double( timespan );
        }
    }

    m_zvStartNext = 0;

    // frames
    do
    {
        const auto zitbegin = std::lower_bound( m_frames.begin(), m_frames.end(), m_zvStart );
        if( zitbegin == m_frames.end() ) break;
        const auto zitend = std::lower_bound( m_frames.begin(), m_frames.end(), m_zvEnd );

        auto zbegin = (int)std::distance( m_frames.begin(), zitbegin );
        if( zbegin > 0 && *zitbegin != m_zvStart ) zbegin--;
        const auto zend = (int)std::distance( m_frames.begin(), zitend );

        for( int i=zbegin; i<zend; i++ )
        {
            const auto ftime = GetFrameTime( i );
            const auto fbegin = (int64_t)GetFrameBegin( i );
            const auto fend = (int64_t)GetFrameEnd( i );

            char buf[128];
            sprintf( buf, "Frame %i (%s)", i, TimeToString( ftime ) );
            const auto tsz = ImGui::CalcTextSize( buf );
            const auto fsz = pxns * ftime;

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns, tsz.y ) ) )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "%s", buf );
                ImGui::Text( "Time from start of program: %s", TimeToString( m_frames[i] - m_frames[0] ) );
                ImGui::EndTooltip();

                if( ImGui::IsMouseClicked( 2 ) )
                {
                    m_zvStartNext = fbegin;
                    m_zvEndNext = fend;
                    m_pause = true;
                }
            }

            if( fbegin >= m_zvStart && fsz > 4 )
            {
                draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, h ), 0x22FFFFFF );
            }

            if( fsz >= 5 )
            {
                if( fbegin >= m_zvStart )
                {
                    draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, 1 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, tsz.y - 1 ), 0xFFFFFFFF );
                }
                if( fend <= m_zvEnd )
                {
                    draw->AddLine( wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, 1 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, tsz.y - 1 ), 0xFFFFFFFF );
                }
                if( fsz - 5 > tsz.x )
                {
                    const auto part = ( fsz - 5 - tsz.x ) / 2;
                    draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, tsz.y / 2 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + part, tsz.y / 2 ), 0xFFFFFFFF );
                    draw->AddText( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2 + part, 0 ), 0xFFFFFFFF, buf );
                    draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2 + part + tsz.x, tsz.y / 2 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, tsz.y / 2 ), 0xFFFFFFFF );
                }
                else
                {
                    draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, tsz.y / 2 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, tsz.y / 2 ), 0xFFFFFFFF );
                }
            }
        }

        const auto fend = GetFrameEnd( zend-1 );
        if( fend == m_zvEnd )
        {
            draw->AddLine( wpos + ImVec2( ( fend - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns, h ), 0x22FFFFFF );
        }
    }
    while( false );

    // zones
    const auto ostep = ImGui::GetFontSize();
    int offset = 20;
    for( auto& v : m_threads )
    {
        draw->AddLine( wpos + ImVec2( 0, offset + ostep - 1 ), wpos + ImVec2( w, offset + ostep - 1 ), 0x33FFFFFF );
        draw->AddText( wpos + ImVec2( 0, offset ), 0xFFFFFFFF, GetThreadString( v->id ) );
        offset += ostep;

        const auto depth = DrawZoneLevel( v->timeline, hover, pxns, wpos, offset, 0 );

        offset += ostep * ( depth + 1.2f );
    }
}

int View::DrawZoneLevel( const Vector<Event*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth )
{
    enum { MinVisSize = 3 };
    int maxdepth = depth;
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - m_delay, [] ( const auto& l, const auto& r ) { return l->end < r; } );
    if( it != vec.end() )
    {
        const auto w = ImGui::GetWindowContentRegionWidth();
        const auto ostep = ImGui::GetFontSize();
        const auto offset = _offset + ostep * depth;
        auto draw = ImGui::GetWindowDrawList();
        const auto dsz = m_delay * pxns;
        const auto rsz = m_resolution * pxns;

        const auto zitend = std::lower_bound( vec.begin(), vec.end(), m_zvEnd + m_resolution, [] ( const auto& l, const auto& r ) { return l->start < r; } );
        while( it < zitend )
        {
            auto& ev = **it;
            auto& srcloc = GetSourceLocation( ev.srcloc );
            const auto color = srcloc.color != 0 ? ( srcloc.color | 0xFF000000 ) : 0xDDDD6666;
            const auto end = GetZoneEnd( ev );
            const auto zsz = ( end - ev.start ) * pxns;
            if( zsz < MinVisSize )
            {
                int num = 1;
                const auto px0 = ( ev.start - m_zvStart ) * pxns;
                auto px1 = ( end - m_zvStart ) * pxns;
                auto rend = end;
                for(;;)
                {
                    ++it;
                    if( it == zitend ) break;
                    auto& srcloc2 = GetSourceLocation( (*it)->srcloc );
                    if( srcloc.color != srcloc2.color ) break;
                    const auto nend = GetZoneEnd( **it );
                    const auto pxnext = ( nend - m_zvStart ) * pxns;
                    if( pxnext - px1 >= MinVisSize * 2 ) break;
                    px1 = pxnext;
                    rend = nend;
                    num++;
                }
                draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ostep ), color, 2.f );
                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ostep ) ) )
                {
                    ImGui::BeginTooltip();
                    ImGui::Text( "Zones too small to display: %i", num );
                    ImGui::Text( "Execution time: %s", TimeToString( rend - ev.start ) );
                    ImGui::EndTooltip();

                    if( ImGui::IsMouseClicked( 2 ) && rend - ev.start > 0 )
                    {
                        m_zvStartNext = ev.start;
                        m_zvEndNext = rend;
                    }
                }
                char tmp[32];
                sprintf( tmp, "%i", num );
                const auto tsz = ImGui::CalcTextSize( tmp );
                if( tsz.x < px1 - px0 )
                {
                    const auto x = px0 + ( px1 - px0 - tsz.x ) / 2;
                    draw->AddText( wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
                }
            }
            else
            {
                const char* zoneName;
                if( ev.text && ev.text->zoneName )
                {
                    zoneName = GetString( ev.text->zoneName );
                }
                else
                {
                    zoneName = GetString( srcloc.function );
                }

                int dmul = 1;
                if( ev.text )
                {
                    if( ev.text->zoneName ) dmul++;
                    if( ev.text->userText ) dmul++;
                }

                const auto tsz = ImGui::CalcTextSize( zoneName );
                const auto pr0 = ( ev.start - m_zvStart ) * pxns;
                const auto pr1 = ( end - m_zvStart ) * pxns;
                const auto px0 = std::max( pr0, -10.0 );
                const auto px1 = std::min( pr1, double( w + 10 ) );
                draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), color, 2.f );
                draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), GetZoneHighlight( ev ), 2.f, -1, GetZoneThickness( ev ) );
                if( dsz * dmul >= MinVisSize )
                {
                    draw->AddRectFilled( wpos + ImVec2( pr0, offset ), wpos + ImVec2( std::min( pr0+dsz*dmul, pr1 ), offset + tsz.y ), 0x882222DD, 2.f );
                    draw->AddRectFilled( wpos + ImVec2( pr1, offset ), wpos + ImVec2( pr1+dsz, offset + tsz.y ), 0x882222DD, 2.f );
                }
                if( rsz >= MinVisSize )
                {
                    draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + tsz.y/2 ), wpos + ImVec2( pr0 - rsz, offset + tsz.y/2 ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + tsz.y/4 ), wpos + ImVec2( pr0 + rsz, offset + 3*tsz.y/4 ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( pr0 - rsz, offset + tsz.y/4 ), wpos + ImVec2( pr0 - rsz, offset + 3*tsz.y/4 ), 0xAAFFFFFF );

                    draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + tsz.y/2 ), wpos + ImVec2( pr1 - rsz, offset + tsz.y/2 ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + tsz.y/4 ), wpos + ImVec2( pr1 + rsz, offset + 3*tsz.y/4 ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( pr1 - rsz, offset + tsz.y/4 ), wpos + ImVec2( pr1 - rsz, offset + 3*tsz.y/4 ), 0xAAFFFFFF );
                }
                if( tsz.x < zsz )
                {
                    const auto x = ( ev.start - m_zvStart ) * pxns + ( ( end - ev.start ) * pxns - tsz.x ) / 2;
                    if( x < 0 || x > w - tsz.x )
                    {
                        ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), true );
                        draw->AddText( wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, zoneName );
                        ImGui::PopClipRect();
                    }
                    else
                    {
                        draw->AddText( wpos + ImVec2( x, offset ), 0xFFFFFFFF, zoneName );
                    }
                }
                else
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), true );
                    draw->AddText( wpos + ImVec2( ( ev.start - m_zvStart ) * pxns, offset ), 0xFFFFFFFF, zoneName );
                    ImGui::PopClipRect();
                }

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ) ) )
                {
                    ZoneTooltip( ev );

                    if( m_zvStartNext == 0 && ImGui::IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( ev );
                    }
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        m_zoneInfoWindow = &ev;
                    }
                }

                if( !ev.child.empty() )
                {
                    const auto d = DrawZoneLevel( ev.child, hover, pxns, wpos, _offset, depth+1 );
                    if( d > maxdepth ) maxdepth = d;
                }

                ++it;
            }
        }
    }
    return maxdepth;
}

void View::DrawZoneInfoWindow()
{
    if( !m_zoneInfoWindow ) return;

    auto& ev = *m_zoneInfoWindow;
    int dmul = 1;

    bool show = true;
    ImGui::Begin( "Zone info", &show, ImGuiWindowFlags_ShowBorders );

    if( ImGui::Button( "Zoom to zone" ) )
    {
        ZoomToZone( ev );
    }
    ImGui::SameLine();
    if( ImGui::Button( "Go to parent" ) )
    {
        if( ev.parent )
        {
            m_zoneInfoWindow = ev.parent;
        }
    }

    ImGui::Separator();

    if( ev.text && ev.text->zoneName )
    {
        ImGui::Text( "Zone name: %s", GetString( ev.text->zoneName ) );
        dmul++;
    }
    auto& srcloc = GetSourceLocation( ev.srcloc );
    ImGui::Text( "Function: %s", GetString( srcloc.function ) );
    ImGui::Text( "Location: %s:%i", GetString( srcloc.file ), srcloc.line );
    if( ev.text && ev.text->userText )
    {
        ImGui::Text( "User text: %s", ev.text->userText );
        dmul++;
    }

    ImGui::Separator();

    const auto end = GetZoneEnd( ev );
    const auto ztime = end - ev.start;
    ImGui::Text( "Time from start of program: %s", TimeToString( ev.start - m_frames[0] ) );
    ImGui::Text( "Execution time: %s", TimeToString( ztime ) );
    ImGui::Text( "Without profiling: %s", TimeToString( ztime - m_delay * dmul ) );

    auto ctt = std::make_unique<uint64_t[]>( ev.child.size() );
    auto cti = std::make_unique<uint32_t[]>( ev.child.size() );
    uint64_t ctime = 0;
    for( int i=0; i<ev.child.size(); i++ )
    {
        const auto cend = GetZoneEnd( *ev.child[i] );
        const auto ct = cend - ev.child[i]->start;
        ctime += ct;
        ctt[i] = ct;
        cti[i] = i;
    }

    std::sort( cti.get(), cti.get() + ev.child.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

    if( !ev.child.empty() )
    {
        const auto ty = ImGui::GetTextLineHeight();
        ImGui::Columns( 2 );
        ImGui::Separator();
        ImGui::Text( "Child zones: %" PRIu64, ev.child.size() );
        ImGui::NextColumn();
        ImGui::Text( "Exclusive time: %s (%.2f%%)", TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
        ImGui::NextColumn();
        ImGui::Separator();
        for( int i=0; i<ev.child.size(); i++ )
        {
            auto& cev = *ev.child[cti[i]];
            if( cev.text && cev.text->zoneName )
            {
                ImGui::Text( "%s", GetString( cev.text->zoneName ) );
            }
            else
            {
                auto& srcloc = GetSourceLocation( cev.srcloc );
                ImGui::Text( "%s", GetString( srcloc.function ) );
            }
            if( ImGui::IsItemHovered() )
            {
                m_zoneHighlight = &cev;
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    m_zoneInfoWindow = &cev;
                }
                if( ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToZone( cev );
                }
                ZoneTooltip( cev );
            }
            ImGui::NextColumn();
            const auto part = double( ctt[cti[i]] ) / ztime;
            char buf[128];
            sprintf( buf, "%s (%.2f%%)", TimeToString( ctt[cti[i]] ), part * 100 );
            ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
        }
        ImGui::EndColumns();
    }

    ImGui::End();

    if( !show ) m_zoneInfoWindow = nullptr;
}

uint32_t View::GetZoneHighlight( const Event& ev )
{
    if( m_zoneInfoWindow == &ev )
    {
        return 0xFF44DD44;
    }
    else if( m_zoneHighlight == &ev )
    {
        return 0xFF4444FF;
    }
    else
    {
        return 0xAAAAAAAA;
    }
}

float View::GetZoneThickness( const Event& ev )
{
    if( m_zoneInfoWindow == &ev || m_zoneHighlight == &ev )
    {
        return 3.f;
    }
    else
    {
        return 1.f;
    }
}

void View::ZoomToZone( const Event& ev )
{
    if( ev.end - ev.start <= 0 ) return;
    m_zvStartNext = ev.start;
    m_zvEndNext = ev.end;
}

void View::ZoneTooltip( const Event& ev )
{
    int dmul = 1;
    if( ev.text )
    {
        if( ev.text->zoneName ) dmul++;
        if( ev.text->userText ) dmul++;
    }

    auto& srcloc = GetSourceLocation( ev.srcloc );

    const auto filename = GetString( srcloc.file );
    const auto line = srcloc.line;

    const char* func;
    const char* zoneName;
    if( ev.text && ev.text->zoneName )
    {
        zoneName = GetString( ev.text->zoneName );
        func = GetString( srcloc.function );
    }
    else
    {
        func = zoneName = GetString( srcloc.function );
    }

    const auto end = GetZoneEnd( ev );

    ImGui::BeginTooltip();
    ImGui::Text( "%s", func );
    ImGui::Text( "%s:%i", filename, line );
    ImGui::Text( "Execution time: %s", TimeToString( end - ev.start ) );
    ImGui::Text( "Without profiling: %s", TimeToString( end - ev.start - m_delay * dmul ) );
    if( ev.text && ev.text->userText )
    {
        ImGui::Text( "" );
        ImGui::TextColored( ImVec4( 0xCC / 255.f, 0xCC / 255.f, 0x22 / 255.f, 1.f ), "%s", ev.text->userText );
    }
    ImGui::EndTooltip();
}

void View::Write( FileWrite& f )
{
    f.Write( &m_delay, sizeof( m_delay ) );
    f.Write( &m_resolution, sizeof( m_resolution ) );
    f.Write( &m_timerMul, sizeof( m_timerMul ) );

    uint64_t sz = m_frames.size();
    f.Write( &sz, sizeof( sz ) );
    f.Write( m_frames.data(), sizeof( uint64_t ) * sz );

    sz = m_strings.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_strings )
    {
        f.Write( &v.first, sizeof( v.first ) );
        sz = v.second.size();
        f.Write( &sz, sizeof( sz ) );
        f.Write( v.second.c_str(), v.second.size() );
    }

    sz = m_threadNames.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_threadNames )
    {
        f.Write( &v.first, sizeof( v.first ) );
        sz = v.second.size();
        f.Write( &sz, sizeof( sz ) );
        f.Write( v.second.c_str(), v.second.size() );
    }

    sz = m_customStrings.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_customStrings )
    {
        uint64_t ptr = (uint64_t)v;
        f.Write( &ptr, sizeof( ptr ) );
        sz = strlen( v );
        f.Write( &sz, sizeof( sz ) );
        f.Write( v, sz );
    }

    sz = m_sourceLocation.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_sourceLocation )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second, sizeof( v.second ) );
    }

    sz = m_threads.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& thread : m_threads )
    {
        f.Write( &thread->id, sizeof( thread->id ) );
        WriteTimeline( f, thread->timeline );
    }
}

void View::WriteTimeline( FileWrite& f, const Vector<Event*>& vec )
{
    uint64_t sz = vec.size();
    f.Write( &sz, sizeof( sz ) );

    for( auto& v : vec )
    {
        f.Write( &v->start, sizeof( v->start ) );
        f.Write( &v->end, sizeof( v->end ) );
        f.Write( &v->srcloc, sizeof( v->srcloc ) );
        if( v->text )
        {
            uint8_t flag = 1;
            f.Write( &flag, sizeof( flag ) );
            f.Write( &v->text->userText, sizeof( v->text->userText ) );
            f.Write( &v->text->zoneName, sizeof( v->text->zoneName ) );
        }
        else
        {
            uint8_t flag = 0;
            f.Write( &flag, sizeof( flag ) );
        }

        WriteTimeline( f, v->child );
    }
}

void View::ReadTimeline( FileRead& f, Vector<Event*>& vec, Event* parent, const std::unordered_map<uint64_t, const char*>& stringMap )
{
    uint64_t sz;
    f.Read( &sz, sizeof( sz ) );
    vec.reserve( sz );

    for( uint64_t i=0; i<sz; i++ )
    {
        auto zone = m_slab.Alloc<Event>();
        m_zonesCnt++;
        vec.push_back( zone );

        f.Read( &zone->start, sizeof( zone->start ) );
        f.Read( &zone->end, sizeof( zone->end ) );
        f.Read( &zone->srcloc, sizeof( zone->srcloc ) );

        uint8_t flag;
        f.Read( &flag, sizeof( flag ) );
        if( flag )
        {
            zone->text = new TextData;
            uint64_t ptr;
            f.Read( &ptr, sizeof( ptr ) );
            zone->text->userText = ptr == 0 ? nullptr : stringMap.find( ptr )->second;
            f.Read( &zone->text->zoneName, sizeof( zone->text->zoneName ) );
        }
        else
        {
            zone->text = nullptr;
        }

        zone->parent = parent;

        ReadTimeline( f, zone->child, zone, stringMap );
    }
}

}
