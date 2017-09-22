#ifdef _MSC_VER
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

#include <algorithm>
#include <assert.h>
#include <limits>
#include <stdlib.h>

#include "../common/TracyProtocol.hpp"
#include "../common/TracySystem.hpp"
#include "../common/TracyQueue.hpp"
#include "TracyImGui.hpp"
#include "TracyView.hpp"

namespace tracy
{

static View* s_instance = nullptr;

View::View( const char* addr )
    : m_addr( addr )
    , m_shutdown( false )
    , m_connected( false )
    , m_hasData( false )
    , m_mbps( 64 )
    , m_stream( LZ4_createStreamDecode() )
    , m_buffer( new char[TargetFrameSize*3] )
    , m_bufferOffset( 0 )
    , m_frameScale( 0 )
    , m_pause( false )
    , m_frameStart( 0 )
    , m_zvStart( 0 )
    , m_zvEnd( 0 )
{
    assert( s_instance == nullptr );
    s_instance = this;

    ImGuiStyle& style = ImGui::GetStyle();
    style.FrameRounding = 2.f;

    m_thread = std::thread( [this] { Worker(); } );
    SetThreadName( m_thread, "Tracy View" );
}

View::~View()
{
    m_shutdown.store( true, std::memory_order_relaxed );
    m_thread.join();

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
        uint64_t timeStart;

        if( !m_sock.Read( &timeStart, sizeof( timeStart ), &tv, ShouldExit ) ) goto close;
        if( !m_sock.Read( &lz4, sizeof( lz4 ), &tv, ShouldExit ) ) goto close;

        m_frames.push_back( timeStart );
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
    if( ev.hdr.type == QueueType::StringData || ev.hdr.type == QueueType::ThreadName )
    {
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000;

        char buf[TargetFrameSize];
        uint16_t sz;
        m_sock.Read( &sz, sizeof( sz ), &tv, ShouldExit );
        m_sock.Read( buf, sz, &tv, ShouldExit );
        if( ev.hdr.type == QueueType::StringData )
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
    if( ev.hdr.type == QueueType::StringData || ev.hdr.type == QueueType::ThreadName )
    {
        uint16_t sz;
        memcpy( &sz, ptr, sizeof( sz ) );
        ptr += sizeof( sz );
        if( ev.hdr.type == QueueType::StringData )
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
    case QueueType::FrameMark:
        ProcessFrameMark( ev.hdr.id );
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

    CheckString( ev.filename );
    CheckString( ev.function );
    CheckThreadString( ev.thread );
    zone->start = ev.time;

    SourceLocation srcloc { ev.filename, ev.function, ev.line };
    auto lit = m_locationRef.find( srcloc );

    std::unique_lock<std::mutex> lock( m_lock );
    if( lit == m_locationRef.end() )
    {
        const auto ref = uint32_t( m_srcFile.size() );
        zone->srcloc = ref;
        m_locationRef.emplace( srcloc, ref );
        m_srcFile.push_back( srcloc );
    }
    else
    {
        zone->srcloc = lit->second;
    }

    if( it == m_pendingEndZone.end() )
    {
        zone->end = -1;
        NewZone( zone, ev.thread );
        lock.unlock();
        m_openZones.emplace( id, zone );
    }
    else
    {
        assert( ev.time <= it->second.time );
        zone->end = it->second.time;
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
        assert( ev.time >= zone->start );
        zone->end = ev.time;
        UpdateZone( zone );
        lock.unlock();
        m_openZones.erase( it );
    }
}

void View::ProcessFrameMark( uint64_t id )
{
    assert( !m_frames.empty() );
    const auto lastframe = m_frames.back();
    if( lastframe < id )
    {
        std::unique_lock<std::mutex> lock( m_lock );
        m_frames.push_back( id );
    }
    else
    {
        auto it = std::lower_bound( m_frames.begin(), m_frames.end(), id );
        std::unique_lock<std::mutex> lock( m_lock );
        m_frames.insert( it, id );
    }
}

void View::CheckString( uint64_t ptr )
{
    if( m_strings.find( ptr ) != m_strings.end() ) return;
    if( m_pendingStrings.find( ptr ) != m_pendingStrings.end() ) return;

    m_pendingStrings.emplace( ptr );

    uint8_t type = ServerQueryString;
    m_sock.Send( &type, sizeof( type ) );
    m_sock.Send( &ptr, sizeof( ptr ) );
}

void View::CheckThreadString( uint64_t id )
{
    if( m_threadNames.find( id ) != m_threadNames.end() ) return;
    if( m_pendingThreads.find( id ) != m_pendingThreads.end() ) return;

    m_pendingThreads.emplace( id );

    uint8_t type = ServerQueryThreadString;
    m_sock.Send( &type, sizeof( type ) );
    m_sock.Send( &id, sizeof( id ) );
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


void View::NewZone( Event* zone, uint64_t thread )
{
    Vector<Event*>* timeline;
    auto it = m_threadMap.find( thread );
    if( it == m_threadMap.end() )
    {
        m_threadMap.emplace( thread, m_threads.size() );
        m_threads.emplace_back( ThreadData { thread } );
        timeline = &m_threads.back().timeline;
    }
    else
    {
        timeline = &m_threads[it->second].timeline;
    }

    if( !timeline->empty() )
    {
        const auto lastend = timeline->back()->end;
        if( lastend != -1 && lastend < zone->start )
        {
            timeline->push_back( zone );
        }
        else
        {

        }
    }
    else
    {
        timeline->push_back( zone );
    }
}

void View::UpdateZone( Event* zone )
{
    assert( zone->end != -1 );
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
        if( !v.timeline.empty() )
        {
            auto ev = v.timeline.back();
            if( ev->end > (int64_t)last ) last = ev->end;
        }
    }
    return last;
}

const char* View::TimeToString( uint64_t ns ) const
{
    enum { Pool = 4 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    if( ns < 1000 )
    {
        sprintf( buf, "%i ns", ns );
    }
    else if( ns < 1000ull * 1000 )
    {
        sprintf( buf, "%.2f us", ns / 1000. );
    }
    else if( ns < 1000ull * 1000 * 1000 )
    {
        sprintf( buf, "%.2f ms", ns / ( 1000. * 1000. ) );
    }
    else if( ns < 1000ull * 1000 * 1000 * 60 )
    {
        sprintf( buf, "%.2f s", ns / ( 1000. * 1000. * 1000. ) );
    }
    else
    {
        const auto m = ns / ( 1000ull * 1000 * 1000 * 60 );
        const auto s = ns - m * ( 1000ull * 1000 * 1000 * 60 );
        sprintf( buf, "%i:%04.1f", m, s / ( 1000. * 1000. * 1000. ) );
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

    // Connection window
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

    ImGui::End();

    // Profiler window
    ImGui::Begin( "Profiler", nullptr, ImGuiWindowFlags_ShowBorders );
    if( ImGui::Button( m_pause ? "Resume" : "Pause", ImVec2( 80, 0 ) ) ) m_pause = !m_pause;
    ImGui::SameLine();
    ImGui::Text( "Frames: %-7i Time span: %-10s View span: %s", m_frames.size(), TimeToString( GetLastTime() - m_frames[0] ), TimeToString( m_zvEnd - m_zvStart ) );
    DrawFrames();
    DrawZones();
    ImGui::End();

    ImGui::ShowTestWindow();
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
        m_zvEnd = m_frames.back();
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
            m_zvStart -= int64_t( delta * nspx );
            m_zvEnd -= int64_t( delta * nspx );
            io.MouseClickedPos[1].x = io.MousePos.x;
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
                m_zvStart += int64_t( p1 * 0.1f );
                m_zvEnd -= int64_t( p2 * 0.1f );
            }
            else if( timespan < 1000ull * 1000 * 1000 * 60 )
            {
                m_zvStart -= std::max( 1ll, int64_t( p1 * 0.1f ) );
                m_zvEnd += std::max( 1ll, int64_t( p2 * 0.1f ) );
            }
            timespan = m_zvEnd - m_zvStart;
            pxns = w / double( timespan );
        }
    }

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
                ImGui::Text( buf );
                ImGui::Text( "Time from start of program: %s", TimeToString( m_frames[i] - m_frames[0] ) );
                ImGui::EndTooltip();
            }

            if( fbegin >= m_zvStart )
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
    int offset = 20;
    for( auto& v : m_threads )
    {
        auto& timeline = v.timeline;
        auto it = std::lower_bound( timeline.begin(), timeline.end(), m_zvStart, [] ( const auto& l, const auto& r ) { return l->end < r; } );
        if( it != timeline.end() )
        {
            const auto zitend = std::lower_bound( timeline.begin(), timeline.end(), m_zvEnd, [] ( const auto& l, const auto& r ) { return l->start < r; } );
            while( it < zitend )
            {
                auto& ev = **it;
                const auto& srcFile = m_srcFile[ev.srcloc];
                const char* func = GetString( srcFile.function );
                const auto zsz = ( ev.end - ev.start ) * pxns;
                const auto tsz = ImGui::CalcTextSize( func );
                draw->AddRectFilled( wpos + ImVec2( ( ev.start - m_zvStart ) * pxns, offset ), wpos + ImVec2( ( ev.end - m_zvStart ) * pxns, offset + tsz.y ), 0xDDDD6666, 2.f );
                draw->AddRect( wpos + ImVec2( ( ev.start - m_zvStart ) * pxns, offset ), wpos + ImVec2( ( ev.end - m_zvStart ) * pxns, offset + tsz.y ), 0xAAAAAAAA, 2.f );
                if( tsz.x < zsz )
                {
                    draw->AddText( wpos + ImVec2( ( ev.start - m_zvStart ) * pxns + ( ( ev.end - ev.start ) * pxns - tsz.x ) / 2, offset ), 0xFFFFFFFF, func );
                }
                else
                {
                    ImGui::PushClipRect( wpos + ImVec2( ( ev.start - m_zvStart ) * pxns, offset ), wpos + ImVec2( ( ev.end - m_zvStart ) * pxns, offset + tsz.y ), true );
                    draw->AddText( wpos + ImVec2( ( ev.start - m_zvStart ) * pxns, offset ), 0xFFFFFFFF, func );
                    ImGui::PopClipRect();
                }

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( ( ev.start - m_zvStart ) * pxns, offset ), wpos + ImVec2( ( ev.end - m_zvStart ) * pxns, offset + tsz.y ) ) )
                {
                    ImGui::BeginTooltip();
                    ImGui::Text( func );
                    ImGui::Text( "%s:%i", GetString( srcFile.filename ), srcFile.line );
                    ImGui::Text( "Execution time: %s", TimeToString( ev.end - ev.start ) );
                    ImGui::EndTooltip();
                }

                it++;
            }
        }

        draw->AddText( wpos + ImVec2( 0, offset ), 0xFFFFFFFF, GetThreadString( v.id ) );

        offset += 20;
    }
}

}
