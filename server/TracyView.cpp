#include <algorithm>
#include <assert.h>
#include <chrono>
#include <inttypes.h>
#include <limits>
#include <math.h>
#include <mutex>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#include "../common/TracySystem.hpp"
#include "tracy_pdqsort.h"
#include "TracyBadVersion.hpp"
#include "TracyFileRead.hpp"
#include "TracyFileWrite.hpp"
#include "TracyImGui.hpp"
#include "TracyPopcnt.hpp"
#include "TracyView.hpp"

#ifdef TRACY_FILESELECTOR
#  include "../nfd/nfd.h"
#endif

#ifndef M_PI_2
#define M_PI_2 1.57079632679489661923
#endif

namespace tracy
{

static const char* TimeToString( int64_t ns )
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
        sprintf( buf, "%s%" PRIi64 " ns", sign, ns );
    }
    else if( ns < 1000ll * 1000 )
    {
        sprintf( buf, "%s%.2f us", sign, ns / 1000. );
    }
    else if( ns < 1000ll * 1000 * 1000 )
    {
        sprintf( buf, "%s%.2f ms", sign, ns / ( 1000. * 1000. ) );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 )
    {
        sprintf( buf, "%s%.2f s", sign, ns / ( 1000. * 1000. * 1000. ) );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 * 60 )
    {
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) );
        const auto s = int64_t( ns - m * ( 1000ll * 1000 * 1000 * 60 ) );
        sprintf( buf, "%s%" PRIi64 ":%04.1f", sign, m, s / ( 1000. * 1000. * 1000. ) );
    }
    else
    {
        const auto h = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 ) );
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) - h * 60 );
        const auto s = int64_t( ns - h * ( 1000ll * 1000 * 1000 * 60 * 60 ) - m * ( 1000ll * 1000 * 1000 * 60 ) );
        sprintf( buf, "%s%" PRIi64 ":%02" PRIi64 ":%02" PRIi64, sign, h, m, int64_t( s / ( 1000ll * 1000 * 1000 ) ) );
    }
    return buf;
}

static const char* TimeToStringInteger( int64_t ns )
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
        sprintf( buf, "%s%" PRIi64 " ns", sign, ns );
    }
    else if( ns < 1000ll * 1000 )
    {
        sprintf( buf, "%s%.0f us", sign, ns / 1000. );
    }
    else if( ns < 1000ll * 1000 * 1000 )
    {
        sprintf( buf, "%s%.0f ms", sign, ns / ( 1000. * 1000. ) );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 )
    {
        sprintf( buf, "%s%.0f s", sign, ns / ( 1000. * 1000. * 1000. ) );
    }
    else
    {
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) );
        const auto s = int64_t( ns - m * ( 1000ll * 1000 * 1000 * 60 ) );
        sprintf( buf, "%s%" PRIi64 ":%02.0f", sign, m, s / ( 1000. * 1000. * 1000. ) );
    }
    return buf;
}

static const char* RealToString( double val, bool separator )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    sprintf( buf, "%f", val );
    auto ptr = buf;
    if( *ptr == '-' ) ptr++;

    const auto vbegin = ptr;

    if( separator )
    {
        while( *ptr != '\0' && *ptr != ',' && *ptr != '.' ) ptr++;
        auto end = ptr;
        while( *end != '\0' ) end++;
        auto sz = end - ptr;

        while( ptr - vbegin > 3 )
        {
            ptr -= 3;
            memmove( ptr+1, ptr, sz );
            *ptr = ',';
            sz += 4;
        }
    }

    while( *ptr != '\0' && *ptr != ',' && *ptr != '.' ) ptr++;

    if( *ptr == '\0' ) return buf;
    while( *ptr != '\0' ) ptr++;
    ptr--;
    while( *ptr == '0' && *ptr != ',' && *ptr != '.' ) ptr--;
    if( *ptr != '.' && *ptr != ',' ) ptr++;
    *ptr = '\0';
    return buf;
}

tracy_force_inline float frexpf_fast( float f, int& power )
{
    float ret;
    int32_t fl;
    memcpy( &fl, &f, 4 );
    power = ( fl >> 23 ) & 0x000000ff;
    power -= 0x7e;
    fl &= 0x807fffff;
    fl |= 0x3f000000;
    memcpy( &ret, &fl, 4 );
    return ret;
}

tracy_force_inline float log2fast( float x )
{
    int e;
    auto f = frexpf_fast( fabsf( x ), e );
    auto t0 = 1.23149591368684f * f - 4.11852516267426f;
    auto t1 = t0 * f + 6.02197014179219f;
    auto t2 = t1 * f - 3.13396450166353f;
    return t2 + e;
}

tracy_force_inline float log10fast( float x )
{
    return log2fast( x ) * 0.301029995663981195213738894724493026768189881462108541310f;    // 1/log2(10)
}

static void TextFocused( const char* label, const char* value )
{
    ImGui::TextDisabled( "%s", label );
    ImGui::SameLine();
    ImGui::Text( "%s", value );
}

enum { MinVisSize = 3 };

static View* s_instance = nullptr;

View::View( const char* addr )
    : m_worker( addr )
    , m_staticView( false )
    , m_frameScale( 0 )
    , m_pause( false )
    , m_frameStart( 0 )
    , m_zvStart( 0 )
    , m_zvEnd( 0 )
    , m_zvHeight( 0 )
    , m_zvScroll( 0 )
    , m_zoneInfoWindow( nullptr )
    , m_lockHighlight { -1 }
    , m_gpuInfoWindow( nullptr )
    , m_callstackInfoWindow( 0 )
    , m_gpuThread( 0 )
    , m_gpuStart( 0 )
    , m_gpuEnd( 0 )
    , m_showOptions( false )
    , m_showMessages( false )
    , m_showStatistics( false )
    , m_drawGpuZones( true )
    , m_drawZones( true )
    , m_drawLocks( true )
    , m_drawPlots( true )
    , m_onlyContendedLocks( false )
    , m_statSort( 0 )
    , m_statSelf( false )
    , m_namespace( Namespace::Full )
{
    assert( s_instance == nullptr );
    s_instance = this;

    ImGuiStyle& style = ImGui::GetStyle();
    style.FrameRounding = 2.f;
}

View::View( FileRead& f )
    : m_worker( f )
    , m_staticView( true )
    , m_frameScale( 0 )
    , m_pause( false )
    , m_frameStart( 0 )
    , m_zvStart( 0 )
    , m_zvEnd( 0 )
    , m_zvHeight( 0 )
    , m_zvScroll( 0 )
    , m_zoneInfoWindow( nullptr )
    , m_gpuInfoWindow( nullptr )
    , m_callstackInfoWindow( 0 )
    , m_gpuThread( 0 )
    , m_gpuStart( 0 )
    , m_gpuEnd( 0 )
    , m_showOptions( false )
    , m_showMessages( false )
    , m_showStatistics( false )
    , m_drawGpuZones( true )
    , m_drawZones( true )
    , m_drawLocks( true )
    , m_drawPlots( true )
    , m_onlyContendedLocks( false )
    , m_statSort( 0 )
    , m_statSelf( false )
    , m_namespace( Namespace::Full )
{
    assert( s_instance == nullptr );
    s_instance = this;
}

View::~View()
{
    m_worker.Shutdown();

    assert( s_instance != nullptr );
    s_instance = nullptr;
}

const char* View::ShortenNamespace( const char* name ) const
{
    if( m_namespace == Namespace::Full ) return name;
    if( m_namespace == Namespace::Short )
    {
        auto ptr = name;
        while( *ptr != '\0' ) ptr++;
        while( ptr > name && *ptr != ':' ) ptr--;
        if( *ptr == ':' ) ptr++;
        return ptr;
    }

    static char buf[1024];
    auto dst = buf;
    auto ptr = name;
    for(;;)
    {
        auto start = ptr;
        while( *ptr != '\0' && *ptr != ':' ) ptr++;
        if( *ptr == '\0' )
        {
            memcpy( dst, start, ptr - start + 1 );
            return buf;
        }
        *dst++ = *start;
        *dst++ = ':';
        while( *ptr == ':' ) ptr++;
    }
}

void View::DrawHelpMarker( const char* desc ) const
{
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos( 450.0f );
        ImGui::TextUnformatted( desc );
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

void View::DrawTextContrast( ImDrawList* draw, const ImVec2& pos, uint32_t color, const char* text )
{
    draw->AddText( pos + ImVec2( 1, 1 ), 0x88000000, text );
    draw->AddText( pos, color, text );
}

bool View::Draw()
{
    return s_instance->DrawImpl();
}

static const char* MainWindowButtons[] = {
    "Resume",
    "Pause"
};

enum { MainWindowButtonsCount = sizeof( MainWindowButtons ) / sizeof( *MainWindowButtons ) };

bool View::DrawImpl()
{
    if( !m_worker.HasData() )
    {
        char tmp[2048];
        sprintf( tmp, "%s###Connection", m_worker.GetAddr().c_str() );
        ImGui::Begin( tmp, nullptr, ImGuiWindowFlags_AlwaysAutoResize );
        ImGui::Text( "Waiting for connection..." );
        ImGui::End();
        return true;
    }

    const auto th = ImGui::GetTextLineHeight();
    float bw = 0;
    for( int i=0; i<MainWindowButtonsCount; i++ )
    {
        bw = std::max( bw, ImGui::CalcTextSize( MainWindowButtons[i] ).x );
    }
    bw += th;

    bool keepOpen = true;
    bool* keepOpenPtr = nullptr;
    if( !m_staticView )
    {
        DrawConnection();
    }
    else
    {
        keepOpenPtr = &keepOpen;
    }

    std::lock_guard<NonRecursiveBenaphore> lock( m_worker.GetDataLock() );
    char tmp[2048];
    sprintf( tmp, "%s###Profiler", m_worker.GetCaptureName().c_str() );
    ImGui::SetNextWindowSize( ImVec2( 1550, 800 ), ImGuiCond_FirstUseEver );
    ImGui::Begin( tmp, keepOpenPtr, ImGuiWindowFlags_NoScrollbar );
    if( !m_worker.IsDataStatic() )
    {
        if( ImGui::Button( m_pause ? MainWindowButtons[0] : MainWindowButtons[1], ImVec2( bw, 0 ) ) ) m_pause = !m_pause;
        ImGui::SameLine();
    }
    if( ImGui::Button( "Options" ) ) m_showOptions = true;
    ImGui::SameLine();
    if( ImGui::Button( "Messages" ) ) m_showMessages = true;
    ImGui::SameLine();
    if( ImGui::Button( "Find Zone" ) ) m_findZone.show = true;
    ImGui::SameLine();
    if( ImGui::Button( "Statistics" ) ) m_showStatistics = true;
    ImGui::SameLine();
    if( ImGui::Button( "Memory" ) ) m_memInfo.show = true;
    ImGui::SameLine();
    if( ImGui::Button( "Compare" ) ) m_compare.show = true;
    ImGui::SameLine();
    if( ImGui::SmallButton( "<" ) ) ZoomToPrevFrame();
    ImGui::SameLine();
    ImGui::Text( "Frames: %" PRIu64, m_worker.GetFrameCount() );
    ImGui::SameLine();
    if( ImGui::SmallButton( ">" ) ) ZoomToNextFrame();
    ImGui::SameLine();
    ImGui::Text( "Time span: %-10s View span: %-10s Zones: %-13s Queue delay: %s  Timer resolution: %s", TimeToString( m_worker.GetLastTime() - m_worker.GetFrameBegin( 0 ) ), TimeToString( m_zvEnd - m_zvStart ), RealToString( m_worker.GetZoneCount(), true ), TimeToString( m_worker.GetDelay() ), TimeToString( m_worker.GetResolution() ) );
    DrawFrames();
    DrawZones();
    ImGui::End();

    m_zoneHighlight = nullptr;
    m_gpuHighlight = nullptr;

    DrawInfoWindow();

    if( m_showOptions ) DrawOptions();
    if( m_showMessages ) DrawMessages();
    if( m_findZone.show ) DrawFindZone();
    if( m_showStatistics ) DrawStatistics();
    if( m_memInfo.show ) DrawMemory();
    if( m_compare.show ) DrawCompare();
    if( m_callstackInfoWindow != 0 ) DrawCallstackWindow();

    if( m_zoomAnim.active )
    {
        const auto& io = ImGui::GetIO();
        m_zoomAnim.progress += io.DeltaTime * m_zoomAnim.lenMod;
        if( m_zoomAnim.progress >= 1.f )
        {
            m_zoomAnim.active = false;
            m_zvStart = m_zoomAnim.start1;
            m_zvEnd = m_zoomAnim.end1;
        }
        else
        {
            const auto v = sqrt( sin( M_PI_2 * m_zoomAnim.progress ) );
            m_zvStart = int64_t( m_zoomAnim.start0 + ( m_zoomAnim.start1 - m_zoomAnim.start0 ) * v );
            m_zvEnd = int64_t( m_zoomAnim.end0 + ( m_zoomAnim.end1 - m_zoomAnim.end0 ) * v );
        }
    }

    return keepOpen;
}

void View::DrawConnection()
{
    const auto ty = ImGui::GetFontSize();
    const auto cs = ty * 0.9f;

    {
        std::lock_guard<NonRecursiveBenaphore> lock( m_worker.GetMbpsDataLock() );
        ImGui::Begin( m_worker.GetAddr().c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize );
        const auto& mbpsVector = m_worker.GetMbpsData();
        const auto mbps = mbpsVector.back();
        char buf[64];
        if( mbps < 0.1f )
        {
            sprintf( buf, "%6.2f Kbps", mbps * 1000.f );
        }
        else
        {
            sprintf( buf, "%6.2f Mbps", mbps );
        }
        ImGui::Dummy( ImVec2( cs, 0 ) );
        ImGui::SameLine();
        ImGui::PlotLines( buf, mbpsVector.data(), mbpsVector.size(), 0, nullptr, 0, std::numeric_limits<float>::max(), ImVec2( 150, 0 ) );
        ImGui::Text( "Ratio %.1f%%  Real: %6.2f Mbps", m_worker.GetCompRatio() * 100.f, mbps / m_worker.GetCompRatio() );
    }

    ImGui::Text( "Memory usage: %.2f MB", memUsage.load( std::memory_order_relaxed ) / ( 1024.f * 1024.f ) );

    const auto wpos = ImGui::GetWindowPos() + ImGui::GetWindowContentRegionMin();
    ImGui::GetWindowDrawList()->AddCircleFilled( wpos + ImVec2( 1 + cs * 0.5, 3 + ty * 0.5 ), cs * 0.5, m_worker.IsConnected() ? 0xFF2222CC : 0xFF444444, 10 );

    std::lock_guard<NonRecursiveBenaphore> lock( m_worker.GetDataLock() );
    {
        const auto sz = m_worker.GetFrameCount();
        if( sz > 1 )
        {
            const auto dt = m_worker.GetFrameTime( sz - 2 );
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
            std::unique_ptr<FileWrite> f;
            const auto sz = strlen( fn );
            if( sz < 7 || memcmp( fn + sz - 6, ".tracy", 6 ) != 0 )
            {
                char tmp[1024];
                sprintf( tmp, "%s.tracy", fn );
                f.reset( FileWrite::Open( tmp ) );
            }
            else
            {
                f.reset( FileWrite::Open( fn ) );
            }
            if( f )
            {
                m_worker.Write( *f );
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
    return frameScale == 0 ? 4 : ( frameScale < 0 ? 6 : 1 );
}

static int GetFrameGroup( int frameScale )
{
    return frameScale < 2 ? 1 : ( 1 << ( frameScale - 1 ) );
}

void View::DrawFrames()
{
    assert( m_worker.GetFrameCount() != 0 );

    const auto Height = 40 * ImGui::GetTextLineHeight() / 15.f;

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
            if( m_frameScale >= 0 ) m_frameScale--;
        }
        else if( wheel < 0 )
        {
            if( m_frameScale < 10 ) m_frameScale++;
        }
    }

    const int fwidth = GetFrameWidth( m_frameScale );
    const int group = GetFrameGroup( m_frameScale );
    const int total = m_worker.GetFrameCount();
    const int onScreen = ( w - 2 ) / fwidth;
    if( !m_pause )
    {
        m_frameStart = ( total < onScreen * group ) ? 0 : total - onScreen * group;
        m_zvStart = m_worker.GetFrameBegin( std::max( 0, total - 4 ) );
        if( total == 1 )
        {
            m_zvEnd = m_worker.GetLastTime();
        }
        else
        {
            m_zvEnd = m_worker.GetFrameBegin( total - 1 );
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
                    auto f = m_worker.GetFrameTime( sel );
                    auto g = std::min( group, total - sel );
                    for( int j=1; j<g; j++ )
                    {
                        f = std::max( f, m_worker.GetFrameTime( sel + j ) );
                    }

                    ImGui::TextDisabled( "Frames:" );
                    ImGui::SameLine();
                    ImGui::Text( "%i - %i (%i)", sel, sel + g - 1, g );
                    ImGui::Separator();
                    TextFocused( "Max frame time:", TimeToString( f ) );
                }
                else
                {
                    const auto offset = m_worker.GetFrameOffset();
                    if( sel == 0 )
                    {
                        ImGui::Text( "Tracy initialization" );
                        ImGui::Separator();
                        TextFocused( "Time:", TimeToString( m_worker.GetFrameTime( sel ) ) );
                    }
                    else if( offset == 0 )
                    {
                        ImGui::TextDisabled( "Frame:" );
                        ImGui::SameLine();
                        ImGui::Text( "%i", sel );
                        ImGui::Separator();
                        TextFocused( "Frame time:", TimeToString( m_worker.GetFrameTime( sel ) ) );
                    }
                    else if( sel == 1 )
                    {
                        ImGui::Text( "Missed frames" );
                        ImGui::Separator();
                        TextFocused( "Time:", TimeToString( m_worker.GetFrameTime( 1 ) ) );
                    }
                    else
                    {
                        ImGui::TextDisabled( "Frame:" );
                        ImGui::SameLine();
                        ImGui::Text( "%i", sel + offset - 1 );
                        ImGui::Separator();
                        TextFocused( "Frame time:", TimeToString( m_worker.GetFrameTime( sel ) ) );
                    }
                }
                TextFocused( "Time from start of program:", TimeToString( m_worker.GetFrameBegin( sel ) - m_worker.GetFrameBegin( 0 ) ) );
                ImGui::EndTooltip();

                if( ImGui::IsMouseClicked( 0 ) )
                {
                    m_pause = true;
                    m_zvStart = m_worker.GetFrameBegin( sel );
                    m_zvEnd = m_worker.GetFrameEnd( sel + group - 1 );
                    if( m_zvStart == m_zvEnd ) m_zvStart--;
                }
                else if( ImGui::IsMouseDragging( 0 ) )
                {
                    m_zvStart = std::min( m_zvStart, m_worker.GetFrameBegin( sel ) );
                    m_zvEnd = std::max( m_zvEnd, m_worker.GetFrameEnd( sel + group - 1 ) );
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
        auto f = m_worker.GetFrameTime( m_frameStart + idx );
        int g;
        if( group > 1 )
        {
            g = std::min( group, total - ( m_frameStart + idx ) );
            for( int j=1; j<g; j++ )
            {
                f = std::max( f, m_worker.GetFrameTime( m_frameStart + idx + j ) );
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

    const std::pair <int, int> zrange = m_worker.GetFrameRange( m_zvStart, m_zvEnd );

    if( zrange.second > m_frameStart && zrange.first < m_frameStart + onScreen * group )
    {
        auto x1 = std::min( onScreen * fwidth, ( zrange.second - m_frameStart ) * fwidth / group );
        auto x0 = std::max( 0, ( zrange.first - m_frameStart ) * fwidth / group );

        if( x0 == x1 ) x1 = x0 + 1;

        draw->AddRectFilled( wpos + ImVec2( 1+x0, 0 ), wpos + ImVec2( 1+x1, Height ), 0x55DD22DD );
    }
}

void View::HandleZoneViewMouse( int64_t timespan, const ImVec2& wpos, float w, double& pxns )
{
    assert( timespan > 0 );
    auto& io = ImGui::GetIO();

    const auto nspx = double( timespan ) / w;

    if( ImGui::IsMouseClicked( 0 ) )
    {
        m_highlight.active = true;
        m_highlight.start = m_highlight.end = m_zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( ImGui::IsMouseDragging( 0, 0 ) )
    {
        m_highlight.end = m_zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else
    {
        m_highlight.active = false;
    }

    if( ImGui::IsMouseDragging( 1, 0 ) )
    {
        m_pause = true;
        const auto delta = ImGui::GetMouseDragDelta( 1, 0 );
        const auto dpx = int64_t( delta.x * nspx );
        if( dpx != 0 )
        {
            m_zvStart -= dpx;
            m_zvEnd -= dpx;
            io.MouseClickedPos[1].x = io.MousePos.x;
        }
        if( delta.y != 0 )
        {
            auto y = ImGui::GetScrollY();
            ImGui::SetScrollY( y - delta.y );
            io.MouseClickedPos[1].y = io.MousePos.y;
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
            m_zvStart += int64_t( p1 * 0.25 );
            m_zvEnd -= int64_t( p2 * 0.25 );
        }
        else if( timespan < 1000ll * 1000 * 1000 * 60 * 60 )
        {
            m_zvStart -= std::max( int64_t( 1 ), int64_t( p1 * 0.25 ) );
            m_zvEnd += std::max( int64_t( 1 ), int64_t( p2 * 0.25 ) );
        }
        timespan = m_zvEnd - m_zvStart;
        pxns = w / double( timespan );
    }
}

static const char* GetFrameText( int i, uint64_t ftime, uint64_t offset )
{
    static char buf[128];
    if( i == 0 )
    {
        sprintf( buf, "Tracy init (%s)", TimeToString( ftime ) );
    }
    else if( offset == 0 )
    {
        sprintf( buf, "Frame %i (%s)", i, TimeToString( ftime ) );
    }
    else if( i == 1 )
    {
        sprintf( buf, "Missed frames (%s)", TimeToString( ftime ) );
    }
    else
    {
        sprintf( buf, "Frame %i (%s)", i + offset - 1, TimeToString( ftime ) );
    }
    return buf;
}

bool View::DrawZoneFrames()
{
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto w = ImGui::GetWindowContentRegionWidth() - ImGui::GetStyle().ScrollbarSize;
    const auto h = ImGui::GetFontSize();
    const auto wh = ImGui::GetContentRegionAvail().y;
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetFontSize();
    const auto fy = round( h * 1.5 );

    ImGui::InvisibleButton( "##zoneFrames", ImVec2( w, h * 2.5 ) );
    bool hover = ImGui::IsItemHovered();

    auto timespan = m_zvEnd - m_zvStart;
    auto pxns = w / double( timespan );

    if( hover ) HandleZoneViewMouse( timespan, wpos, w, pxns );

    {
        const auto nspx = 1.0 / pxns;
        const auto scale = std::max( 0.0, round( log10( nspx ) + 2 ) );
        const auto step = pow( 10, scale );

        const auto dx = step * pxns;
        double x = 0;
        int tw = 0;
        int tx = 0;
        int64_t tt = 0;
        while( x < w )
        {
            draw->AddLine( wpos + ImVec2( x, 0 ), wpos + ImVec2( x, round( ty * 0.5 ) ), 0x66FFFFFF );
            if( tw == 0 )
            {
                char buf[128];
                const auto t = m_zvStart - m_worker.GetFrameBegin( 0 );
                auto txt = TimeToString( t );
                if( t >= 0 )
                {
                    sprintf( buf, "+%s", txt );
                    txt = buf;
                }
                draw->AddText( wpos + ImVec2( x, round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                tw = ImGui::CalcTextSize( txt ).x;
            }
            else if( x > tx + tw + ty * 2 )
            {
                tx = x;
                auto txt = TimeToString( tt );
                draw->AddText( wpos + ImVec2( x, round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                tw = ImGui::CalcTextSize( txt ).x;
            }

            for( int i=1; i<5; i++ )
            {
                draw->AddLine( wpos + ImVec2( x + i * dx / 10, 0 ), wpos + ImVec2( x + i * dx / 10, round( ty * 0.25 ) ), 0x33FFFFFF );
            }
            draw->AddLine( wpos + ImVec2( x + 5 * dx / 10, 0 ), wpos + ImVec2( x + 5 * dx / 10, round( ty * 0.375 ) ), 0x33FFFFFF );
            for( int i=6; i<10; i++ )
            {
                draw->AddLine( wpos + ImVec2( x + i * dx / 10, 0 ), wpos + ImVec2( x + i * dx / 10, round( ty * 0.25 ) ), 0x33FFFFFF );
            }

            x += dx;
            tt += step;
        }
    }

    const std::pair <int, int> zrange = m_worker.GetFrameRange( m_zvStart, m_zvEnd );
    if( zrange.first < 0 ) return hover;

    for( int i = zrange.first; i < zrange.second; i++ )
    {
        const auto ftime = m_worker.GetFrameTime( i );
        const auto fbegin = m_worker.GetFrameBegin( i );
        const auto fend = m_worker.GetFrameEnd( i );
        const auto fsz = pxns * ftime;

        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, fy ), wpos + ImVec2( ( fend - m_zvStart ) * pxns, fy + ty ) ) )
        {
            ImGui::BeginTooltip();
            ImGui::Text( "%s", GetFrameText( i, ftime, m_worker.GetFrameOffset() ) );
            ImGui::Separator();
            TextFocused( "Time from start of program:", TimeToString( m_worker.GetFrameBegin( i ) - m_worker.GetFrameBegin( 0 ) ) );
            ImGui::EndTooltip();

            if( ImGui::IsMouseClicked( 2 ) )
            {
                ZoomToRange( fbegin, fend );
            }
        }

        if( fsz <= 4 ) continue;

        if( fbegin >= m_zvStart )
        {
            draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, wh ), 0x22FFFFFF );
        }

        if( fsz >= 5 )
        {
            auto buf = GetFrameText( i, ftime, m_worker.GetFrameOffset() );
            auto tx = ImGui::CalcTextSize( buf ).x;
            uint32_t color = i == 0 ? 0xFF4444FF : 0xFFFFFFFF;

            if( fsz - 5 <= tx )
            {
                buf = TimeToString( ftime );
                tx = ImGui::CalcTextSize( buf ).x;
            }

            if( fbegin >= m_zvStart )
            {
                draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, fy + 1 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, fy + ty - 1 ), color );
            }
            if( fend <= m_zvEnd )
            {
                draw->AddLine( wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, fy + 1 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, fy + ty - 1 ), color );
            }
            if( fsz - 5 > tx )
            {
                const auto part = ( fsz - 5 - tx ) / 2;
                draw->AddLine( wpos + ImVec2( std::max( -10.0, ( fbegin - m_zvStart ) * pxns + 2 ), fy + round( ty / 2 ) ), wpos + ImVec2( std::min( w + 20.0, ( fbegin - m_zvStart ) * pxns + part ), fy + round( ty / 2 ) ), color );
                draw->AddText( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2 + part, fy ), color, buf );
                draw->AddLine( wpos + ImVec2( std::max( -10.0, ( fbegin - m_zvStart ) * pxns + 2 + part + tx ), fy + round( ty / 2 ) ), wpos + ImVec2( std::min( w + 20.0, ( fend - m_zvStart ) * pxns - 2 ), fy + round( ty / 2 ) ), color );
            }
            else
            {
                draw->AddLine( wpos + ImVec2( std::max( -10.0, ( fbegin - m_zvStart ) * pxns + 2 ), fy + round( ty / 2 ) ), wpos + ImVec2( std::min( w + 20.0, ( fend - m_zvStart ) * pxns - 2 ), fy + round( ty / 2 ) ), color );
            }
        }
    }

    const auto fend = m_worker.GetFrameEnd( zrange.second-1 );
    if( fend == m_zvEnd )
    {
        draw->AddLine( wpos + ImVec2( ( fend - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns, wh ), 0x22FFFFFF );
    }

    return hover;
}

void View::DrawZones()
{
    m_msgHighlight = nullptr;

    if( m_zvStart == m_zvEnd ) return;
    assert( m_zvStart < m_zvEnd );

    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if( window->SkipItems ) return;

    m_gpuThread = 0;
    m_gpuStart = 0;
    m_gpuEnd = 0;

    const auto linepos = ImGui::GetCursorScreenPos();
    const auto lineh = ImGui::GetContentRegionAvail().y;

    auto drawMouseLine = DrawZoneFrames();

    ImGui::BeginChild( "##zoneWin", ImVec2( ImGui::GetWindowContentRegionWidth(), ImGui::GetContentRegionAvail().y ), false, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_NoScrollWithMouse );

    window = ImGui::GetCurrentWindow();
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto h = std::max<float>( m_zvHeight, ImGui::GetContentRegionAvail().y - 4 );    // magic border value
    auto draw = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton( "##zones", ImVec2( w, h ) );
    bool hover = ImGui::IsItemHovered();

    const auto timespan = m_zvEnd - m_zvStart;
    auto pxns = w / double( timespan );

    if( hover )
    {
        drawMouseLine = true;
        HandleZoneViewMouse( timespan, wpos, w, pxns );
    }

    const auto nspx = 1.0 / pxns;

    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    int offset = 0;
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;

    const auto yMin = linepos.y;
    const auto yMax = yMin + lineh;

    // gpu zones
    if( m_drawGpuZones )
    {
        for( size_t i=0; i<m_worker.GetGpuData().size(); i++ )
        {
            const auto& v = m_worker.GetGpuData()[i];
            if( !Visible( v ) ) continue;
            bool& showFull = ShowFull( v );

            const auto yPos = wpos.y + offset;
            if( yPos + ostep >= yMin && yPos <= yMax )
            {
                draw->AddLine( wpos + ImVec2( 0, offset + ostep - 1 ), wpos + ImVec2( w, offset + ostep - 1 ), 0x33FFFFFF );

                if( showFull )
                {
                    draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), 0xFFFFAAAA );
                }
                else
                {
                    draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), 0xFF886666 );
                }
                const bool isVulkan = v->thread == 0;
                char buf[64];
                if( isVulkan )
                {
                    sprintf( buf, "Vulkan context %zu", i );
                }
                else
                {
                    sprintf( buf, "OpenGL context %zu", i );
                }
                draw->AddText( wpos + ImVec2( ty, offset ), showFull ? 0xFFFFAAAA : 0xFF886666, buf );

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + ImGui::CalcTextSize( buf ).x, offset + ty ) ) )
                {
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        showFull = !showFull;
                    }

                    ImGui::BeginTooltip();
                    ImGui::Text( "%s", buf );
                    ImGui::Separator();
                    if( !isVulkan )
                    {
                        TextFocused( "Thread:", m_worker.GetThreadString( v->thread ) );
                    }
                    if( !v->timeline.empty() )
                    {
                        const auto t = v->timeline.front()->gpuStart;
                        if( t != std::numeric_limits<int64_t>::max() )
                        {
                            TextFocused( "Appeared at", TimeToString( t - m_worker.GetFrameBegin( 0 ) ) );
                        }
                    }
                    TextFocused( "Zone count:", RealToString( v->count, true ) );
                    TextFocused( "Top-level zones:", RealToString( v->timeline.size(), true ) );
                    if( isVulkan )
                    {
                        TextFocused( "Timestamp accuracy:", TimeToString( v->period ) );
                    }
                    else
                    {
                        ImGui::TextDisabled( "Query accuracy bits:" );
                        ImGui::SameLine();
                        ImGui::Text( "%i", v->accuracyBits );
                    }
                    ImGui::EndTooltip();
                }
            }

            offset += ostep;
            if( showFull && !v->timeline.empty() && v->timeline.front()->gpuStart != std::numeric_limits<int64_t>::max() )
            {
                const auto begin = v->timeline.front()->gpuStart;
                const auto drift = GpuDrift( v );
                const auto depth = DispatchGpuZoneLevel( v->timeline, hover, pxns, wpos, offset, 0, v->thread, yMin, yMax, begin, drift );
                offset += ostep * depth;
            }
            offset += ostep * 0.2f;
        }
    }

    // zones
    LockHighlight nextLockHighlight { -1 };
    for( const auto& v : m_worker.GetThreadData() )
    {
        if( !Visible( v ) ) continue;
        bool& showFull = ShowFull( v );

        const auto yPos = wpos.y + offset;
        if( yPos + ostep >= yMin && yPos <= yMax )
        {
            draw->AddLine( wpos + ImVec2( 0, offset + ostep - 1 ), wpos + ImVec2( w, offset + ostep - 1 ), 0x33FFFFFF );

            if( showFull )
            {
                draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), 0xFFFFFFFF );

                auto it = std::lower_bound( v->messages.begin(), v->messages.end(), m_zvStart, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
                auto end = std::lower_bound( it, v->messages.end(), m_zvEnd, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );

                while( it < end )
                {
                    const auto next = std::upper_bound( it, v->messages.end(), (*it)->time + MinVisSize * nspx, [] ( const auto& lhs, const auto& rhs ) { return lhs < rhs->time; } );
                    const auto dist = std::distance( it, next );

                    const auto px = ( (*it)->time - m_zvStart ) * pxns;
                    if( dist > 1 )
                    {
                        draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.5, offset + to ), wpos + ImVec2( px + (ty - to) * 0.5, offset + to ), wpos + ImVec2( px, offset + to + th ), 0xFFDDDDDD );
                    }
                    draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, offset + to ), wpos + ImVec2( px + (ty - to) * 0.5, offset + to ), wpos + ImVec2( px, offset + to + th ), 0xFFDDDDDD );
                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, offset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, offset + ty ) ) )
                    {
                        ImGui::BeginTooltip();
                        if( dist > 1 )
                        {
                            ImGui::Text( "%i messages", (int)dist );
                        }
                        else
                        {
                            ImGui::Text( "%s", TimeToString( (*it)->time - m_worker.GetFrameBegin( 0 ) ) );
                            ImGui::Separator();
                            ImGui::Text( "Message text:" );
                            ImGui::TextColored( ImVec4( 0xCC / 255.f, 0xCC / 255.f, 0x22 / 255.f, 1.f ), "%s", m_worker.GetString( (*it)->ref ) );
                        }
                        ImGui::EndTooltip();
                        m_msgHighlight = *it;
                    }
                    it = next;
                }
            }
            else
            {
                draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), 0xFF888888 );
            }
            const auto txt = m_worker.GetThreadString( v->id );
            const auto txtsz = ImGui::CalcTextSize( txt );
            if( m_gpuThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtsz.x + 4, offset + ty ), 0x448888DD );
                draw->AddRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtsz.x + 4, offset + ty ), 0x888888DD );
            }
            if( m_gpuInfoWindow && m_gpuInfoWindowThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtsz.x + 4, offset + ty ), 0x4488DD88 );
                draw->AddRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtsz.x + 4, offset + ty ), 0x8888DD88 );
            }
            draw->AddText( wpos + ImVec2( ty, offset ), showFull ? 0xFFFFFFFF : 0xFF888888, txt );

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtsz.x, offset + ty ) ) )
            {
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    showFull = !showFull;
                }

                ImGui::BeginTooltip();
                ImGui::Text( "%s", m_worker.GetThreadString( v->id ) );
                if( !v->timeline.empty() )
                {
                    ImGui::Separator();
                    TextFocused( "Appeared at", TimeToString( v->timeline.front()->start - m_worker.GetFrameBegin( 0 ) ) );
                    TextFocused( "Zone count:", RealToString( v->count, true ) );
                    TextFocused( "Top-level zones:", RealToString( v->timeline.size(), true ) );
                }
                ImGui::EndTooltip();
            }
        }

        offset += ostep;

        if( showFull )
        {
            m_lastCpu = -1;
            if( m_drawZones )
            {
                const auto depth = DispatchZoneLevel( v->timeline, hover, pxns, wpos, offset, 0, yMin, yMax );
                offset += ostep * depth;
            }

            if( m_drawLocks )
            {
                const auto depth = DrawLocks( v->id, hover, pxns, wpos, offset, nextLockHighlight, yMin, yMax );
                offset += ostep * depth;
            }
        }
        offset += ostep * 0.2f;
    }
    m_lockHighlight = nextLockHighlight;

    if( m_drawPlots )
    {
        offset = DrawPlots( offset, pxns, wpos, hover, yMin, yMax );
    }

    const auto scrollPos = ImGui::GetScrollY();
    if( scrollPos == 0 && m_zvScroll != 0 )
    {
        m_zvHeight = 0;
    }
    else
    {
        if( offset > m_zvHeight ) m_zvHeight = offset;
    }
    m_zvScroll = scrollPos;

    ImGui::EndChild();

    if( m_gpuStart != 0 && m_gpuEnd != 0 )
    {
        const auto px0 = ( m_gpuStart - m_zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_gpuEnd - m_zvStart ) * pxns );
        draw->AddRectFilled( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x228888DD );
        draw->AddRect( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x448888DD );
    }
    if( m_gpuInfoWindow )
    {
        const auto px0 = ( m_gpuInfoWindow->cpuStart - m_zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_gpuInfoWindow->cpuEnd - m_zvStart ) * pxns );
        draw->AddRectFilled( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x2288DD88 );
        draw->AddRect( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x4488DD88 );
    }

    if( m_highlight.active && m_highlight.start != m_highlight.end )
    {
        const auto s = std::min( m_highlight.start, m_highlight.end );
        const auto e = std::max( m_highlight.start, m_highlight.end );
        draw->AddRectFilled( ImVec2( wpos.x + ( s - m_zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_zvStart ) * pxns, linepos.y + lineh ), 0x22DD8888 );
        draw->AddRect( ImVec2( wpos.x + ( s - m_zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_zvStart ) * pxns, linepos.y + lineh ), 0x44DD8888 );

        ImGui::BeginTooltip();
        ImGui::Text( "%s", TimeToString( e - s ) );
        ImGui::EndTooltip();
    }
    else if( drawMouseLine )
    {
        auto& io = ImGui::GetIO();
        draw->AddLine( ImVec2( io.MousePos.x, linepos.y ), ImVec2( io.MousePos.x, linepos.y + lineh ), 0x33FFFFFF );
    }

    if( m_memInfo.show && m_memInfo.restrictTime )
    {
        const auto zvMid = ( m_zvEnd - m_zvStart ) / 2;
        auto& io = ImGui::GetIO();
        draw->AddLine( ImVec2( wpos.x + zvMid * pxns, linepos.y ), ImVec2( wpos.x + zvMid * pxns, linepos.y + lineh ), 0x88FF44FF );
    }
}

int View::DispatchZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax )
{
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;

    const auto yPos = wpos.y + offset;
    if( yPos + ostep >= yMin && yPos <= yMax )
    {
        return DrawZoneLevel( vec, hover, pxns, wpos, _offset, depth, yMin, yMax );
    }
    else
    {
        return SkipZoneLevel( vec, hover, pxns, wpos, _offset, depth, yMin, yMax );
    }
}

int View::DrawZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - delay, [] ( const auto& l, const auto& r ) { return (uint64_t)l->end < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_zvEnd + resolution, [] ( const auto& l, const auto& r ) { return l->start < r; } );
    if( it == zitend ) return depth;

    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;
    auto draw = ImGui::GetWindowDrawList();
    const auto dsz = delay * pxns;
    const auto rsz = resolution * pxns;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = **it;
        const auto color = GetZoneColor( ev );
        const auto end = m_worker.GetZoneEnd( ev );
        const auto zsz = std::max( ( end - ev.start ) * pxns, pxns * 0.5 );
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
                const auto nend = m_worker.GetZoneEnd( **it );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
                rend = nend;
                num++;
            }
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ), color );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ) ) )
            {
                if( num > 1 )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Zones too small to display:", RealToString( num, true ) );
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( rend - ev.start ) );
                    ImGui::EndTooltip();

                    if( ImGui::IsMouseClicked( 2 ) && rend - ev.start > 0 )
                    {
                        ZoomToRange( ev.start, rend );
                    }
                }
                else
                {
                    ZoneTooltip( ev );

                    if( ImGui::IsMouseClicked( 2 ) && rend - ev.start > 0 )
                    {
                        ZoomToZone( ev );
                    }
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        ShowZoneInfo( ev );
                    }
                }
            }
            char tmp[32];
            sprintf( tmp, "%i", num );
            const auto tsz = ImGui::CalcTextSize( tmp );
            if( tsz.x < px1 - px0 )
            {
                const auto x = px0 + ( px1 - px0 - tsz.x ) / 2;
                DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
            }
        }
        else
        {
            const char* zoneName = m_worker.GetZoneName( ev );
            int dmul = ev.text.active ? 2 : 1;

            bool migration = false;
            if( m_lastCpu != ev.cpu_start )
            {
                if( m_lastCpu >= 0 )
                {
                    migration = true;
                }
                m_lastCpu = ev.cpu_start;
            }

            if( !ev.child.empty() )
            {
                const auto d = DispatchZoneLevel( ev.child, hover, pxns, wpos, _offset, depth, yMin, yMax );
                if( d > maxdepth ) maxdepth = d;
            }

            if( ev.end >= 0 && m_lastCpu != ev.cpu_end )
            {
                m_lastCpu = ev.cpu_end;
                migration = true;
            }

            auto tsz = ImGui::CalcTextSize( zoneName );
            if( tsz.x > zsz )
            {
                zoneName = ShortenNamespace( zoneName );
                tsz = ImGui::CalcTextSize( zoneName );
            }

            const auto pr0 = ( ev.start - m_zvStart ) * pxns;
            const auto pr1 = ( end - m_zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );
            draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), color );
            draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), GetZoneHighlight( ev, migration ), 0.f, -1, GetZoneThickness( ev ) );
            if( dsz * dmul >= MinVisSize )
            {
                draw->AddRectFilled( wpos + ImVec2( pr0, offset ), wpos + ImVec2( std::min( pr0+dsz*dmul, pr1 ), offset + tsz.y ), 0x882222DD );
                draw->AddRectFilled( wpos + ImVec2( pr1, offset ), wpos + ImVec2( pr1+dsz, offset + tsz.y ), 0x882222DD );
            }
            if( rsz >= MinVisSize )
            {
                draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + round( tsz.y/2 ) ), wpos + ImVec2( pr0 - rsz, offset + round( tsz.y/2 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr0 + rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr0 - rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr0 - rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );

                draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + round( tsz.y/2 ) ), wpos + ImVec2( pr1 - rsz, offset + round( tsz.y/2 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr1 + rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr1 - rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr1 - rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
            }
            if( tsz.x < zsz )
            {
                const auto x = ( ev.start - m_zvStart ) * pxns + ( ( end - ev.start ) * pxns - tsz.x ) / 2;
                if( x < 0 || x > w - tsz.x )
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, zoneName );
                    ImGui::PopClipRect();
                }
                else if( ev.start == ev.end )
                {
                    DrawTextContrast( draw, wpos + ImVec2( px0 + ( px1 - px0 - tsz.x ) * 0.5, offset ), 0xFFFFFFFF, zoneName );
                }
                else
                {
                    DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFFFFFFFF, zoneName );
                }
            }
            else
            {
                ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                DrawTextContrast( draw, wpos + ImVec2( ( ev.start - m_zvStart ) * pxns, offset ), 0xFFFFFFFF, zoneName );
                ImGui::PopClipRect();
            }

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ) ) )
            {
                ZoneTooltip( ev );

                if( !m_zoomAnim.active && ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToZone( ev );
                }
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    ShowZoneInfo( ev );
                }
            }

            ++it;
        }
    }
    return maxdepth;
}

int View::SkipZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - delay, [] ( const auto& l, const auto& r ) { return (uint64_t)l->end < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_zvEnd + resolution, [] ( const auto& l, const auto& r ) { return l->start < r; } );
    if( it == zitend ) return depth;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = **it;
        const auto end = m_worker.GetZoneEnd( ev );
        const auto zsz = std::max( ( end - ev.start ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            auto px1 = ( end - m_zvStart ) * pxns;
            for(;;)
            {
                ++it;
                if( it == zitend ) break;
                const auto nend = m_worker.GetZoneEnd( **it );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
            }
        }
        else
        {
            m_lastCpu = ev.cpu_start;

            if( !ev.child.empty() )
            {
                const auto d = DispatchZoneLevel( ev.child, hover, pxns, wpos, _offset, depth, yMin, yMax );
                if( d > maxdepth ) maxdepth = d;
            }

            if( ev.end >= 0 && m_lastCpu != ev.cpu_end )
            {
                m_lastCpu = ev.cpu_end;
            }

            ++it;
        }
    }
    return maxdepth;
}

int View::DispatchGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
{
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;

    const auto yPos = wpos.y + offset;
    if( yPos + ostep >= yMin && yPos <= yMax )
    {
        return DrawGpuZoneLevel( vec, hover, pxns, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
    }
    else
    {
        return SkipGpuZoneLevel( vec, hover, pxns, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
    }
}

static int64_t AdjustGpuTime( int64_t time, int64_t begin, int drift )
{
    const auto t = time - begin;
    return time + t / 1000000000 * drift;
}

int View::DrawGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - delay, [begin, drift] ( const auto& l, const auto& r ) { return (uint64_t)AdjustGpuTime( l->gpuEnd, begin, drift ) < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_zvEnd + resolution, [begin, drift] ( const auto& l, const auto& r ) { return AdjustGpuTime( l->gpuStart, begin, drift ) < r; } );
    if( it == zitend ) return depth;

    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;
    auto draw = ImGui::GetWindowDrawList();
    const auto dsz = delay * pxns;
    const auto rsz = resolution * pxns;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = **it;
        const auto color = GetZoneColor( ev );
        auto end = m_worker.GetZoneEnd( ev );
        if( end == std::numeric_limits<int64_t>::max() ) break;
        const auto start = AdjustGpuTime( ev.gpuStart, begin, drift );
        end = AdjustGpuTime( end, begin, drift );
        const auto zsz = std::max( ( end - start ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            int num = 1;
            const auto px0 = ( start - m_zvStart ) * pxns;
            auto px1 = ( end - m_zvStart ) * pxns;
            auto rend = end;
            for(;;)
            {
                ++it;
                if( it == zitend ) break;
                const auto nend = AdjustGpuTime( m_worker.GetZoneEnd( **it ), begin, drift );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
                rend = nend;
                num++;
            }
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ), color );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ) ) )
            {
                if( num > 1 )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Zones too small to display:", RealToString( num, true ) );
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( rend - start ) );
                    ImGui::EndTooltip();

                    if( ImGui::IsMouseClicked( 2 ) && rend - start > 0 )
                    {
                        ZoomToRange( start, rend );
                    }
                }
                else
                {
                    ZoneTooltip( ev );

                    if( ImGui::IsMouseClicked( 2 ) && rend - start > 0 )
                    {
                        ZoomToZone( ev );
                    }
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        ShowZoneInfo( ev, thread );
                    }

                    m_gpuThread = thread;
                    m_gpuStart = ev.cpuStart;
                    m_gpuEnd = ev.cpuEnd;
                }
            }
            char tmp[32];
            sprintf( tmp, "%i", num );
            const auto tsz = ImGui::CalcTextSize( tmp );
            if( tsz.x < px1 - px0 )
            {
                const auto x = px0 + ( px1 - px0 - tsz.x ) / 2;
                DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
            }
        }
        else
        {
            if( !ev.child.empty() )
            {
                const auto d = DispatchGpuZoneLevel( ev.child, hover, pxns, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
                if( d > maxdepth ) maxdepth = d;
            }

            const char* zoneName = m_worker.GetZoneName( ev );
            auto tsz = ImGui::CalcTextSize( zoneName );

            const auto pr0 = ( start - m_zvStart ) * pxns;
            const auto pr1 = ( end - m_zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );
            draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), color );
            draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), GetZoneHighlight( ev ), 0.f, -1, GetZoneThickness( ev ) );
            if( dsz >= MinVisSize )
            {
                draw->AddRectFilled( wpos + ImVec2( pr0, offset ), wpos + ImVec2( std::min( pr0+dsz, pr1 ), offset + tsz.y ), 0x882222DD );
                draw->AddRectFilled( wpos + ImVec2( pr1, offset ), wpos + ImVec2( pr1+dsz, offset + tsz.y ), 0x882222DD );
            }
            if( rsz >= MinVisSize )
            {
                draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + round( tsz.y/2 ) ), wpos + ImVec2( pr0 - rsz, offset + round( tsz.y/2 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr0 + rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr0 - rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr0 - rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );

                draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + round( tsz.y/2 ) ), wpos + ImVec2( pr1 - rsz, offset + round( tsz.y/2 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr1 + rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr1 - rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr1 - rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
            }
            if( tsz.x < zsz )
            {
                const auto x = ( start - m_zvStart ) * pxns + ( ( end - start ) * pxns - tsz.x ) / 2;
                if( x < 0 || x > w - tsz.x )
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, zoneName );
                    ImGui::PopClipRect();
                }
                else if( ev.gpuStart == ev.gpuEnd )
                {
                    DrawTextContrast( draw, wpos + ImVec2( px0 + ( px1 - px0 - tsz.x ) * 0.5, offset ), 0xFFFFFFFF, zoneName );
                }
                else
                {
                    DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFFFFFFFF, zoneName );
                }
            }
            else
            {
                ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                DrawTextContrast( draw, wpos + ImVec2( ( start - m_zvStart ) * pxns, offset ), 0xFFFFFFFF, zoneName );
                ImGui::PopClipRect();
            }

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ) ) )
            {
                ZoneTooltip( ev );

                if( !m_zoomAnim.active && ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToZone( ev );
                }
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    ShowZoneInfo( ev, thread );
                }

                m_gpuThread = thread;
                m_gpuStart = ev.cpuStart;
                m_gpuEnd = ev.cpuEnd;
            }

            ++it;
        }
    }
    return maxdepth;
}

int View::SkipGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - delay, [begin, drift] ( const auto& l, const auto& r ) { return (uint64_t)AdjustGpuTime( l->gpuEnd, begin, drift ) < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_zvEnd + resolution, [begin, drift] ( const auto& l, const auto& r ) { return AdjustGpuTime( l->gpuStart, begin, drift ) < r; } );
    if( it == zitend ) return depth;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = **it;
        auto end = m_worker.GetZoneEnd( ev );
        if( end == std::numeric_limits<int64_t>::max() ) break;
        const auto start = AdjustGpuTime( ev.gpuStart, begin, drift );
        end = AdjustGpuTime( end, begin, drift );
        const auto zsz = std::max( ( end - start ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            auto px1 = ( end - m_zvStart ) * pxns;
            for(;;)
            {
                ++it;
                if( it == zitend ) break;
                const auto nend = AdjustGpuTime( m_worker.GetZoneEnd( **it ), begin, drift );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
            }
        }
        else
        {
            if( !ev.child.empty() )
            {
                const auto d = DispatchGpuZoneLevel( ev.child, hover, pxns, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
                if( d > maxdepth ) maxdepth = d;
            }
            ++it;
        }
    }
    return maxdepth;
}

static inline uint64_t GetThreadBit( uint8_t thread )
{
    return uint64_t( 1 ) << thread;
}

static inline bool IsThreadWaiting( uint64_t bitlist, uint64_t threadBit )
{
    return ( bitlist & threadBit ) != 0;
}

static inline bool AreOtherWaiting( uint64_t bitlist, uint64_t threadBit )
{
    return ( bitlist & ~threadBit ) != 0;
}

enum class LockState
{
    Nothing,
    HasLock,            // green
    HasBlockingLock,    // yellow
    WaitLock            // red
};

static Vector<LockEvent*>::const_iterator GetNextLockEvent( const Vector<LockEvent*>::const_iterator& it, const Vector<LockEvent*>::const_iterator& end, LockState& nextState, uint64_t threadBit )
{
    auto next = it;
    next++;

    switch( nextState )
    {
    case LockState::Nothing:
        while( next < end )
        {
            if( (*next)->lockCount != 0 )
            {
                if( GetThreadBit( (*next)->lockingThread ) == threadBit )
                {
                    nextState = AreOtherWaiting( (*next)->waitList, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                    break;
                }
                else if( IsThreadWaiting( (*next)->waitList, threadBit ) )
                {
                    nextState = LockState::WaitLock;
                    break;
                }
            }
            next++;
        }
        break;
    case LockState::HasLock:
        while( next < end )
        {
            if( (*next)->lockCount == 0 )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( (*next)->waitList != 0 )
            {
                if( AreOtherWaiting( (*next)->waitList, threadBit ) )
                {
                    nextState = LockState::HasBlockingLock;
                }
                break;
            }
            if( (*next)->waitList != (*it)->waitList || (*next)->lockCount != (*it)->lockCount )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::HasBlockingLock:
        while( next < end )
        {
            if( (*next)->lockCount == 0 )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( (*next)->waitList != (*it)->waitList || (*next)->lockCount != (*it)->lockCount )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::WaitLock:
        while( next < end )
        {
            if( GetThreadBit( (*next)->lockingThread ) == threadBit )
            {
                nextState = AreOtherWaiting( (*next)->waitList, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            if( (*next)->lockingThread != (*it)->lockingThread )
            {
                break;
            }
            if( (*next)->lockCount == 0 )
            {
                break;
            }
            next++;
        }
        break;
    default:
        assert( false );
        break;
    }

    return next;
}

static Vector<LockEvent*>::const_iterator GetNextLockEventShared( const Vector<LockEvent*>::const_iterator& it, const Vector<LockEvent*>::const_iterator& end, LockState& nextState, uint64_t threadBit )
{
    const auto itptr = (const LockEventShared*)*it;
    auto next = it;
    next++;

    switch( nextState )
    {
    case LockState::Nothing:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)*next;
            if( ptr->lockCount != 0 )
            {
                const auto wait = ptr->waitList | ptr->waitShared;
                if( GetThreadBit( ptr->lockingThread ) == threadBit )
                {
                    nextState = AreOtherWaiting( wait, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                    break;
                }
                else if( IsThreadWaiting( wait, threadBit ) )
                {
                    nextState = LockState::WaitLock;
                    break;
                }
            }
            else if( IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = ( ptr->waitList != 0 ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            else if( ptr->sharedList != 0 && IsThreadWaiting( ptr->waitList, threadBit ) )
            {
                nextState = LockState::WaitLock;
                break;
            }
            next++;
        }
        break;
    case LockState::HasLock:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)*next;
            if( ptr->lockCount == 0 && !IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( ptr->waitList != 0 )
            {
                if( AreOtherWaiting( ptr->waitList, threadBit ) )
                {
                    nextState = LockState::HasBlockingLock;
                }
                break;
            }
            else if( !IsThreadWaiting( ptr->sharedList, threadBit ) && ptr->waitShared != 0 )
            {
                nextState = LockState::HasBlockingLock;
                break;
            }
            if( ptr->waitList != itptr->waitList || ptr->waitShared != itptr->waitShared || ptr->lockCount != itptr->lockCount || ptr->sharedList != itptr->sharedList )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::HasBlockingLock:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)*next;
            if( ptr->lockCount == 0 && !IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( ptr->waitList != itptr->waitList || ptr->waitShared != itptr->waitShared || ptr->lockCount != itptr->lockCount || ptr->sharedList != itptr->sharedList )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::WaitLock:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)*next;
            if( GetThreadBit( ptr->lockingThread ) == threadBit )
            {
                const auto wait = ptr->waitList | ptr->waitShared;
                nextState = AreOtherWaiting( wait, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            if( IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = ( ptr->waitList != 0 ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            if( ptr->lockingThread != itptr->lockingThread )
            {
                break;
            }
            if( ptr->lockCount == 0 && !IsThreadWaiting( ptr->waitShared, threadBit ) )
            {
                break;
            }
            next++;
        }
        break;
    default:
        assert( false );
        break;
    }

    return next;
}

static LockState CombineLockState( LockState state, LockState next )
{
    return (LockState)std::max( (int)state, (int)next );
}

int View::DrawLocks( uint64_t tid, bool hover, double pxns, const ImVec2& wpos, int _offset, LockHighlight& highlight, float yMin, float yMax )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    const auto w = ImGui::GetWindowContentRegionWidth();
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    auto draw = ImGui::GetWindowDrawList();
    const auto dsz = delay * pxns;
    const auto rsz = resolution * pxns;

    int cnt = 0;
    for( const auto& v : m_worker.GetLockMap() )
    {
        const auto& lockmap = v.second;
        if( !lockmap.valid || !Visible( &lockmap ) ) continue;

        auto it = lockmap.threadMap.find( tid );
        if( it == lockmap.threadMap.end() ) continue;

        const auto& tl = lockmap.timeline;
        assert( !tl.empty() );
        if( tl.back()->time < m_zvStart ) continue;

        auto GetNextLockFunc = lockmap.type == LockType::Lockable ? GetNextLockEvent : GetNextLockEventShared;

        const auto thread = it->second;
        const auto threadBit = GetThreadBit( thread );

        auto vbegin = std::lower_bound( tl.begin(), tl.end(), m_zvStart - delay, [] ( const auto& l, const auto& r ) { return l->time < r; } );
        const auto vend = std::lower_bound( vbegin, tl.end(), m_zvEnd + resolution, [] ( const auto& l, const auto& r ) { return l->time < r; } );

        if( vbegin > tl.begin() ) vbegin--;

        const auto offset = _offset + ostep * cnt;

        LockState state = LockState::Nothing;
        if( lockmap.type == LockType::Lockable )
        {
            if( (*vbegin)->lockCount != 0 )
            {
                if( (*vbegin)->lockingThread == thread )
                {
                    state = AreOtherWaiting( (*vbegin)->waitList, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                }
                else if( IsThreadWaiting( (*vbegin)->waitList, threadBit ) )
                {
                    state = LockState::WaitLock;
                }
            }
        }
        else
        {
            const auto ptr = (LockEventShared*)*vbegin;
            if( ptr->lockCount != 0 )
            {
                if( ptr->lockingThread == thread )
                {
                    state = ( AreOtherWaiting( ptr->waitList, threadBit ) || AreOtherWaiting( ptr->waitShared, threadBit ) ) ? LockState::HasBlockingLock : LockState::HasLock;
                }
                else if( IsThreadWaiting( ptr->waitList, threadBit ) || IsThreadWaiting( ptr->waitShared, threadBit ) )
                {
                    state = LockState::WaitLock;
                }
            }
            else if( IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                state = ptr->waitList != 0 ? LockState::HasBlockingLock : LockState::HasLock;
            }
            else if( ptr->sharedList != 0 && IsThreadWaiting( ptr->waitList, threadBit ) )
            {
                state = LockState::WaitLock;
            }
        }

        const auto yPos = wpos.y + offset;
        if( yPos + ostep >= yMin && yPos <= yMax )
        {
            bool drawn = false;
            const auto& srcloc = m_worker.GetSourceLocation( lockmap.srcloc );

            double pxend = 0;
            for(;;)
            {
                while( vbegin < vend && ( state == LockState::Nothing || ( m_onlyContendedLocks && state == LockState::HasLock ) ) )
                {
                    vbegin = GetNextLockFunc( vbegin, vend, state, threadBit );
                }
                if( vbegin >= vend ) break;

                assert( state != LockState::Nothing && ( !m_onlyContendedLocks || state != LockState::HasLock ) );
                drawn = true;

                LockState drawState = state;
                auto next = GetNextLockFunc( vbegin, vend, state, threadBit );

                const auto t0 = (*vbegin)->time;
                int64_t t1 = next == tl.end() ? m_lastTime : (*next)->time;
                const auto px0 = std::max( pxend, ( t0 - m_zvStart ) * pxns );
                auto tx0 = px0;
                double px1 = ( t1 - m_zvStart ) * pxns;
                uint64_t condensed = 0;

                for(;;)
                {
                    if( next >= vend || px1 - tx0 > MinVisSize ) break;
                    auto n = next;
                    auto ns = state;
                    while( n < vend && ( ns == LockState::Nothing || ( m_onlyContendedLocks && ns == LockState::HasLock ) ) )
                    {
                        n = GetNextLockFunc( n, vend, ns, threadBit );
                    }
                    if( n >= vend ) break;
                    if( n == next )
                    {
                        n = GetNextLockFunc( n, vend, ns, threadBit );
                    }
                    drawState = CombineLockState( drawState, state );
                    condensed++;
                    const auto t2 = n == tl.end() ? m_lastTime : (*n)->time;
                    const auto px2 = ( t2 - m_zvStart ) * pxns;
                    if( px2 - px1 > MinVisSize ) break;
                    if( drawState != ns && px2 - px0 > MinVisSize && !( ns == LockState::Nothing || ( m_onlyContendedLocks && ns == LockState::HasLock ) ) ) break;
                    t1 = t2;
                    tx0 = px1;
                    px1 = px2;
                    next = n;
                    state = ns;
                }

                pxend = std::max( { px1, px0+MinVisSize, px0 + pxns * 0.5 } );

                bool itemHovered = hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ) );
                if( itemHovered )
                {
                    if( condensed > 1 )
                    {
                        ImGui::BeginTooltip();
                        TextFocused( "Multiple lock events:", RealToString( condensed, true ) );
                        ImGui::EndTooltip();
                    }
                    else
                    {
                        highlight.blocked = drawState == LockState::HasBlockingLock;
                        if( !highlight.blocked )
                        {
                            highlight.id = v.first;
                            highlight.begin = t0;
                            highlight.end = t1;
                            highlight.thread = thread;
                            highlight.blocked = false;
                        }
                        else
                        {
                            auto b = vbegin;
                            while( b != tl.begin() )
                            {
                                if( (*b)->lockingThread != (*vbegin)->lockingThread )
                                {
                                    break;
                                }
                                b--;
                            }
                            b++;
                            highlight.begin = (*b)->time;

                            auto e = next;
                            while( e != tl.end() )
                            {
                                if( (*e)->lockingThread != (*next)->lockingThread )
                                {
                                    highlight.id = v.first;
                                    highlight.end = (*e)->time;
                                    highlight.thread = thread;
                                    break;
                                }
                                e++;
                            }
                        }

                        ImGui::BeginTooltip();
                        ImGui::Text( "Lock #%" PRIu32 ": %s", v.first, m_worker.GetString( srcloc.function ) );
                        ImGui::Separator();
                        ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
                        TextFocused( "Time:", TimeToString( t1 - t0 ) );
                        ImGui::Separator();

                        uint32_t markloc = 0;
                        auto it = vbegin;
                        for(;;)
                        {
                            if( (*it)->thread == thread )
                            {
                                if( ( (*it)->lockingThread == thread || IsThreadWaiting( (*it)->waitList, threadBit ) ) && (*it)->srcloc != 0 )
                                {
                                    markloc = (*it)->srcloc;
                                    break;
                                }
                            }
                            if( it == tl.begin() ) break;
                            --it;
                        }
                        if( markloc != 0 )
                        {
                            const auto& marklocdata = m_worker.GetSourceLocation( markloc );
                            ImGui::Text( "Lock event location:" );
                            ImGui::Text( "%s", m_worker.GetString( marklocdata.function ) );
                            ImGui::Text( "%s:%i", m_worker.GetString( marklocdata.file ), marklocdata.line );
                            ImGui::Separator();
                        }

                        if( v.second.type == LockType::Lockable )
                        {
                            switch( drawState )
                            {
                            case LockState::HasLock:
                                if( (*vbegin)->lockCount == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadString( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has %i locks. No other threads are waiting.", m_worker.GetThreadString( tid ), (*vbegin)->lockCount );
                                }
                                if( (*vbegin)->waitList != 0 )
                                {
                                    assert( !AreOtherWaiting( (*next)->waitList, threadBit ) );
                                    ImGui::Text( "Recursive lock acquire in thread." );
                                }
                                break;
                            case LockState::HasBlockingLock:
                            {
                                if( (*vbegin)->lockCount == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%i):", m_worker.GetThreadString( tid ), TracyCountBits( (*vbegin)->waitList ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has %i locks. Blocked threads (%i):", m_worker.GetThreadString( tid ), (*vbegin)->lockCount, TracyCountBits( (*vbegin)->waitList ) );
                                }
                                auto waitList = (*vbegin)->waitList;
                                int t = 0;
                                ImGui::Indent( ty );
                                while( waitList != 0 )
                                {
                                    if( waitList & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
                                    }
                                    waitList >>= 1;
                                    t++;
                                }
                                ImGui::Unindent( ty );
                                break;
                            }
                            case LockState::WaitLock:
                            {
                                if( (*vbegin)->lockCount > 0 )
                                {
                                    ImGui::Text( "Thread \"%s\" is blocked by other thread:", m_worker.GetThreadString( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadString( tid ) );
                                }
                                ImGui::Indent( ty );
                                ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[(*vbegin)->lockingThread] ) );
                                ImGui::Unindent( ty );
                                break;
                            }
                            default:
                                assert( false );
                                break;
                            }
                        }
                        else
                        {
                            const auto ptr = (const LockEventShared*)*vbegin;
                            switch( drawState )
                            {
                            case LockState::HasLock:
                                assert( ptr->waitList == 0 );
                                if( ptr->sharedList == 0 )
                                {
                                    assert( ptr->lockCount == 1 );
                                    ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadString( tid ) );
                                }
                                else if( TracyCountBits( ptr->sharedList ) == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has a sole shared lock. No other threads are waiting.", m_worker.GetThreadString( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has shared lock. No other threads are waiting.", m_worker.GetThreadString( tid ) );
                                    ImGui::Text( "Threads sharing the lock (%i):", TracyCountBits( ptr->sharedList ) - 1 );
                                    auto sharedList = ptr->sharedList;
                                    int t = 0;
                                    ImGui::Indent( ty );
                                    while( sharedList != 0 )
                                    {
                                        if( sharedList & 0x1 && t != thread )
                                        {
                                            ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
                                        }
                                        sharedList >>= 1;
                                        t++;
                                    }
                                    ImGui::Unindent( ty );
                                }
                                break;
                            case LockState::HasBlockingLock:
                            {
                                if( ptr->sharedList == 0 )
                                {
                                    assert( ptr->lockCount == 1 );
                                    ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%i):", m_worker.GetThreadString( tid ), TracyCountBits( ptr->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }
                                else if( TracyCountBits( ptr->sharedList ) == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has a sole shared lock. Blocked threads (%i):", m_worker.GetThreadString( tid ), TracyCountBits( ptr->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has shared lock.", m_worker.GetThreadString( tid ) );
                                    ImGui::Text( "Threads sharing the lock (%i):", TracyCountBits( ptr->sharedList ) - 1 );
                                    auto sharedList = ptr->sharedList;
                                    int t = 0;
                                    ImGui::Indent( ty );
                                    while( sharedList != 0 )
                                    {
                                        if( sharedList & 0x1 && t != thread )
                                        {
                                            ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
                                        }
                                        sharedList >>= 1;
                                        t++;
                                    }
                                    ImGui::Unindent( ty );
                                    ImGui::Text( "Blocked threads (%i):", TracyCountBits( ptr->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }

                                auto waitList = ptr->waitList;
                                int t = 0;
                                ImGui::Indent( ty );
                                while( waitList != 0 )
                                {
                                    if( waitList & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
                                    }
                                    waitList >>= 1;
                                    t++;
                                }
                                auto waitShared = ptr->waitShared;
                                t = 0;
                                while( waitShared != 0 )
                                {
                                    if( waitShared & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
                                    }
                                    waitShared >>= 1;
                                    t++;
                                }
                                ImGui::Unindent( ty );
                                break;
                            }
                            case LockState::WaitLock:
                            {
                                assert( ptr->lockCount == 0 || ptr->lockCount == 1 );
                                if( ptr->lockCount != 0 || ptr->sharedList != 0 )
                                {
                                    ImGui::Text( "Thread \"%s\" is blocked by other threads (%i):", m_worker.GetThreadString( tid ), ptr->lockCount + TracyCountBits( ptr->sharedList ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadString( tid ) );
                                }
                                ImGui::Indent( ty );
                                if( ptr->lockCount != 0 )
                                {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[ptr->lockingThread] ) );
                                }
                                auto sharedList = ptr->sharedList;
                                int t = 0;
                                while( sharedList != 0 )
                                {
                                    if( sharedList & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
                                    }
                                    sharedList >>= 1;
                                    t++;
                                }
                                ImGui::Unindent( ty );
                                break;
                            }
                            default:
                                assert( false );
                                break;
                            }
                        }
                        ImGui::EndTooltip();
                    }
                }

                const auto cfilled  = drawState == LockState::HasLock ? 0xFF228A22 : ( drawState == LockState::HasBlockingLock ? 0xFF228A8A : 0xFF2222BD );
                draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ), cfilled );
                if( m_lockHighlight.thread != thread && ( drawState == LockState::HasBlockingLock ) != m_lockHighlight.blocked && next != tl.end() && m_lockHighlight.id == int64_t( v.first ) && m_lockHighlight.begin <= (*vbegin)->time && m_lockHighlight.end >= (*next)->time )
                {
                    const auto t = uint8_t( ( sin( std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch() ).count() * 0.01 ) * 0.5 + 0.5 ) * 255 );
                    draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ), 0x00FFFFFF | ( t << 24 ), 0.f, -1, 2.f );
                }
                else if( condensed == 0 )
                {
                    const auto coutline = drawState == LockState::HasLock ? 0xFF3BA33B : ( drawState == LockState::HasBlockingLock ? 0xFF3BA3A3 : 0xFF3B3BD6 );
                    draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ), coutline );
                }

                const auto rx0 = ( t0 - m_zvStart ) * pxns;
                if( dsz >= MinVisSize )
                {
                    draw->AddRectFilled( wpos + ImVec2( rx0, offset ), wpos + ImVec2( std::min( rx0+dsz, px1 ), offset + ty ), 0x882222DD );
                }
                if( rsz >= MinVisSize )
                {
                    draw->AddLine( wpos + ImVec2( rx0 + rsz, offset + round( ty/2 ) ), wpos + ImVec2( rx0 - rsz, offset + round( ty/2 ) ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( rx0 + rsz, offset + round( ty/4 ) ), wpos + ImVec2( rx0 + rsz, offset + round( 3*ty/4 ) ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( rx0 - rsz, offset + round( ty/4 ) ), wpos + ImVec2( rx0 - rsz, offset + round( 3*ty/4 ) ), 0xAAFFFFFF );

                    draw->AddLine( wpos + ImVec2( px1 + rsz, offset + round( ty/2 ) ), wpos + ImVec2( px1 - rsz, offset + round( ty/2 ) ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( px1 + rsz, offset + round( ty/4 ) ), wpos + ImVec2( px1 + rsz, offset + round( 3*ty/4 ) ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( px1 - rsz, offset + round( ty/4 ) ), wpos + ImVec2( px1 - rsz, offset + round( 3*ty/4 ) ), 0xAAFFFFFF );
                }

                vbegin = next;
            }

            if( drawn )
            {
                char buf[1024];
                sprintf( buf, "%" PRIu32 ": %s", v.first, m_worker.GetString( srcloc.function ) );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0xFF8888FF, buf );
                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + ImGui::CalcTextSize( buf ).x, offset + ty ) ) )
                {
                    ImGui::BeginTooltip();
                    switch( v.second.type )
                    {
                    case LockType::Lockable:
                        TextFocused( "Type:", "lockable" );
                        break;
                    case LockType::SharedLockable:
                        TextFocused( "Type:", "shared lockable" );
                        break;
                    default:
                        assert( false );
                        break;
                    }
                    ImGui::Text( "Thread list:" );
                    ImGui::Separator();
                    ImGui::Indent( ty );
                    for( const auto& t : v.second.threadList )
                    {
                        ImGui::Text( "%s", m_worker.GetThreadString( t ) );
                    }
                    ImGui::Unindent( ty );
                    ImGui::Separator();
                    TextFocused( "Lock events:", RealToString( v.second.timeline.size(), true ) );
                    ImGui::EndTooltip();
                }
                cnt++;
            }
        }
        else
        {
            while( vbegin < vend && ( state == LockState::Nothing || ( m_onlyContendedLocks && state == LockState::HasLock ) ) )
            {
                vbegin = GetNextLockFunc( vbegin, vend, state, threadBit );
            }
            if( vbegin < vend ) cnt++;
        }
    }
    return cnt;
}

int View::DrawPlots( int offset, double pxns, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    const auto PlotHeight = 100 * ImGui::GetTextLineHeight() / 15.f;

    enum { MaxPoints = 512 };
    float tmpvec[MaxPoints*2];

    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto ty = ImGui::GetFontSize();
    auto draw = ImGui::GetWindowDrawList();
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;
    const auto nspx = 1.0 / pxns;

    for( const auto& v : m_worker.GetPlots() )
    {
        if( !Visible( v ) ) continue;
        assert( !v->data.empty() );
        bool& showFull = ShowFull( v );

        float txtx;
        auto yPos = wpos.y + offset;
        if( yPos + ty >= yMin && yPos <= yMax )
        {
            if( showFull )
            {
                draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), 0xFF44DDDD );
            }
            else
            {
                draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), 0xFF226E6E );
            }
            const auto txt = GetPlotName( v );
            txtx = ImGui::CalcTextSize( txt ).x;
            draw->AddText( wpos + ImVec2( ty, offset ), showFull ? 0xFF44DDDD : 0xFF226E6E, txt );
            draw->AddLine( wpos + ImVec2( 0, offset + ty - 1 ), wpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtx, offset + ty ) ) )
            {
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    showFull = !showFull;
                }

                const auto tr = v->data.back().time - v->data.front().time;

                ImGui::BeginTooltip();
                ImGui::Text( "Plot \"%s\"", txt );
                ImGui::Separator();
                TextFocused( "Data points:", RealToString( v->data.size(), true ) );
                TextFocused( "Data range:", RealToString( v->max - v->min, true ) );
                TextFocused( "Min value:", RealToString( v->min, true ) );
                TextFocused( "Max value:", RealToString( v->max, true ) );
                TextFocused( "Time range:", TimeToString( tr ) );
                TextFocused( "Data/second:", RealToString( double( v->data.size() ) / tr * 1000000000ll, true ) );

                const auto it = std::lower_bound( v->data.begin(), v->data.end(), v->data.back().time - 1000000000ll * 10, [] ( const auto& l, const auto& r ) { return l.time < r; } );
                const auto tr10 = v->data.back().time - it->time;
                if( tr10 != 0 )
                {
                    TextFocused( "D/s (10s):", RealToString( double( std::distance( it, v->data.end() ) ) / tr10 * 1000000000ll, true ) );
                }

                ImGui::EndTooltip();
            }
        }

        offset += ty;

        if( showFull )
        {
            auto yPos = wpos.y + offset;
            if( yPos + PlotHeight >= yMin && yPos <= yMax )
            {
                const auto& vec = v->data;
                auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - m_worker.GetDelay(), [] ( const auto& l, const auto& r ) { return l.time < r; } );
                auto end = std::lower_bound( it, vec.end(), m_zvEnd + m_worker.GetResolution(), [] ( const auto& l, const auto& r ) { return l.time < r; } );

                if( end != vec.end() ) end++;
                if( it != vec.begin() ) it--;

                double min = it->val;
                double max = it->val;
                if( std::distance( it, end ) > 1000000 )
                {
                    min = v->min;
                    max = v->max;
                }
                else
                {
                    auto tmp = it;
                    ++tmp;
                    const auto sz = end - tmp;
                    for( ptrdiff_t i=0; i<sz; i++ )
                    {
                        min = tmp[i].val < min ? tmp[i].val : min;
                        max = tmp[i].val > max ? tmp[i].val : max;
                    }
                    tmp += sz;
                }

                const auto revrange = 1.0 / ( max - min );

                if( it == vec.begin() )
                {
                    const auto x = ( it->time - m_zvStart ) * pxns;
                    const auto y = PlotHeight - ( it->val - min ) * revrange * PlotHeight;
                    DrawPlotPoint( wpos, x, y, offset, 0xFF44DDDD, hover, false, it, 0, false, v->type, PlotHeight );
                }

                auto prevx = it;
                auto prevy = it;
                ++it;
                ptrdiff_t skip = 0;
                while( it < end )
                {
                    const auto x0 = ( prevx->time - m_zvStart ) * pxns;
                    const auto x1 = ( it->time - m_zvStart ) * pxns;
                    const auto y0 = PlotHeight - ( prevy->val - min ) * revrange * PlotHeight;
                    const auto y1 = PlotHeight - ( it->val - min ) * revrange * PlotHeight;

                    draw->AddLine( wpos + ImVec2( x0, offset + y0 ), wpos + ImVec2( x1, offset + y1 ), 0xFF44DDDD );

                    const auto rx = skip == 0 ? 2.0 : ( skip == 1 ? 2.5 : 4.0 );

                    auto range = std::upper_bound( it, end, int64_t( it->time + nspx * rx ), [] ( const auto& l, const auto& r ) { return l < r.time; } );
                    assert( range > it );
                    const auto rsz = std::distance( it, range );
                    if( rsz == 1 )
                    {
                        DrawPlotPoint( wpos, x1, y1, offset, 0xFF44DDDD, hover, true, it, prevy->val, false, v->type, PlotHeight );
                        prevx = it;
                        prevy = it;
                        ++it;
                    }
                    else
                    {
                        prevx = it;

                        skip = rsz / MaxPoints;
                        const auto skip1 = std::max<ptrdiff_t>( 1, skip );
                        const auto sz = rsz / skip1 + 1;
                        assert( sz <= MaxPoints*2 );

                        auto dst = tmpvec;
                        for(;;)
                        {
                            *dst++ = float( it->val );
                            if( std::distance( it, range ) > skip1 )
                            {
                                it += skip1;
                            }
                            else
                            {
                                break;
                            }
                        }
                        pdqsort_branchless( tmpvec, dst );

                        draw->AddLine( wpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), wpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), 0xFF44DDDD );

                        auto vit = tmpvec;
                        while( vit != dst )
                        {
                            auto vrange = std::upper_bound( vit, dst, *vit + 3.0 / ( revrange * PlotHeight ), [] ( const auto& l, const auto& r ) { return l < r; } );
                            assert( vrange > vit );
                            if( std::distance( vit, vrange ) == 1 )
                            {
                                DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, false, PlotHeight );
                            }
                            else
                            {
                                DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, true, PlotHeight );
                            }
                            vit = vrange;
                        }

                        prevy = it - 1;
                    }
                }

                char tmp[64];
                if( yPos + ty >= yMin && yPos <= yMax )
                {
                    sprintf( tmp, "(y-range: %s)", RealToString( max - min, true ) );
                    draw->AddText( wpos + ImVec2( ty * 1.5f + txtx, offset - ty ), 0x8844DDDD, tmp );
                }
                sprintf( tmp, "%s", RealToString( max, true ) );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );
                offset += PlotHeight - ty;
                sprintf( tmp, "%s", RealToString( min, true ) );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );

                draw->AddLine( wpos + ImVec2( 0, offset + ty - 1 ), wpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );
                offset += ty;
            }
            else
            {
                offset += PlotHeight;
            }
        }
        offset += 0.2 * ty;
    }

    return offset;
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged, float PlotHeight )
{
    auto draw = ImGui::GetWindowDrawList();
    if( merged )
    {
        draw->AddRectFilled( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );
    }
    else
    {
        draw->AddRect( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );
    }

    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x - 2, offset ), wpos + ImVec2( x + 2, offset + PlotHeight ) ) )
    {
        ImGui::BeginTooltip();
        TextFocused( "Value:", RealToString( val, true ) );
        if( hasPrev )
        {
            TextFocused( "Change:", RealToString( val - prev, true ) );
        }
        ImGui::EndTooltip();
    }
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, const PlotItem* item, double prev, bool merged, PlotType type, float PlotHeight )
{
    auto draw = ImGui::GetWindowDrawList();
    if( merged )
    {
        draw->AddRectFilled( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );
    }
    else
    {
        draw->AddRect( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );
    }

    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x - 2, offset ), wpos + ImVec2( x + 2, offset + PlotHeight ) ) )
    {
        ImGui::BeginTooltip();
        TextFocused( "Value:", RealToString( item->val, true ) );
        if( hasPrev )
        {
            const auto change = item->val - prev;
            TextFocused( "Change:", RealToString( change, true ) );

            if( type == PlotType::Memory )
            {
                auto& mem = m_worker.GetMemData();
                const MemEvent* ev = nullptr;
                if( change > 0 )
                {
                    auto it = std::lower_bound( mem.data.begin(), mem.data.end(), item->time, [] ( const auto& lhs, const auto& rhs ) { return lhs.timeAlloc < rhs; } );
                    if( it != mem.data.end() && it->timeAlloc == item->time )
                    {
                        ev = it;
                    }
                }
                else
                {
                    const auto& data = mem.data;
                    auto it = std::lower_bound( mem.frees.begin(), mem.frees.end(), item->time, [&data] ( const auto& lhs, const auto& rhs ) { return data[lhs].timeFree < rhs; } );
                    if( it != mem.frees.end() && data[*it].timeFree == item->time )
                    {
                        ev = &data[*it];
                    }
                }
                if( ev )
                {
                    ImGui::Separator();
                    ImGui::TextDisabled( "Address:" );
                    ImGui::SameLine();
                    ImGui::Text( "0x%" PRIx64, ev->ptr );
                    TextFocused( "Appeared at", TimeToString( ev->timeAlloc - m_worker.GetFrameBegin( 0 ) ) );
                    if( change > 0 )
                    {
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(this event)" );
                    }
                    if( ev->timeFree < 0 )
                    {
                        ImGui::Text( "Allocation still active" );
                    }
                    else
                    {
                        TextFocused( "Freed at", TimeToString( ev->timeFree - m_worker.GetFrameBegin( 0 ) ) );
                        if( change < 0 )
                        {
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(this event)" );
                        }
                        TextFocused( "Duration:", TimeToString( ev->timeFree - ev->timeAlloc ) );
                    }
                    uint64_t tid;
                    if( change > 0 )
                    {
                        tid = m_worker.DecompressThread( ev->threadAlloc );
                    }
                    else
                    {
                        tid = m_worker.DecompressThread( ev->threadFree );
                    }
                    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(0x%" PRIX64 ")", tid );

                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        m_memInfo.show = true;
                        sprintf( m_memInfo.pattern, "0x%" PRIx64, ev->ptr );
                        m_memInfo.ptrFind = ev->ptr;
                    }
                }
            }
        }
        ImGui::EndTooltip();
    }
}

void View::DrawInfoWindow()
{
    if( m_zoneInfoWindow )
    {
        DrawZoneInfoWindow();
    }
    else if( m_gpuInfoWindow )
    {
        DrawGpuInfoWindow();
    }
}

template<typename T>
void DrawZoneTrace( T zone, const std::vector<T>& trace, const Worker& worker, std::function<void(T)> showZone )
{
    bool expand = ImGui::TreeNode( "Zone trace" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( trace.size(), true ) );
    if( !expand ) return;

    if( !trace.empty() )
    {
        T prev = zone;
        const auto sz = trace.size();
        for( size_t i=0; i<sz; i++ )
        {
            auto curr = trace[i];
            if( prev->callstack == 0 || curr->callstack == 0 )
            {
                ImGui::TextDisabled( "[unknown frames]" );
            }
            else if( prev->callstack != curr->callstack )
            {
                auto& prevCs = worker.GetCallstack( prev->callstack );
                auto& currCs = worker.GetCallstack( curr->callstack );

                const auto psz = int8_t( prevCs.size() );
                int8_t idx;
                for( idx=0; idx<psz; idx++ )
                {
                    auto pf = prevCs[idx];
                    bool found = false;
                    for( auto& cf : currCs )
                    {
                        if( cf == pf )
                        {
                            idx--;
                            found = true;
                            break;
                        }
                    }
                    if( found ) break;
                }
                for( int8_t j=1; j<idx; j++ )
                {
                    auto frame = worker.GetCallstackFrame( prevCs[j] );
                    ImGui::TextDisabled( "%s", worker.GetString( frame->name ) );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    if( frame->line == 0 )
                    {
                        ImGui::TextDisabled( "%s", worker.GetString( frame->file ) );
                    }
                    else
                    {
                        ImGui::TextDisabled( "%s:%i", worker.GetString( frame->file ), frame->line );
                    }
                }
            }

            showZone( curr );
            prev = curr;
        }
    }

    auto last = trace.empty() ? zone : trace.back();
    if( last->callstack == 0 )
    {
        ImGui::TextDisabled( "[unknown frames]" );
    }
    else
    {
        auto& cs = worker.GetCallstack( last->callstack );
        const auto csz = cs.size();
        for( uint8_t i=1; i<csz; i++ )
        {
            auto frame = worker.GetCallstackFrame( cs[i] );
            ImGui::TextDisabled( "%s", worker.GetString( frame->name ) );
            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
            if( frame->line == 0 )
            {
                ImGui::TextDisabled( "%s", worker.GetString( frame->file ) );
            }
            else
            {
                ImGui::TextDisabled( "%s:%i", worker.GetString( frame->file ), frame->line );
            }
        }
    }

    ImGui::TreePop();
}

void View::DrawZoneInfoWindow()
{
    auto& ev = *m_zoneInfoWindow;
    int dmul = 1;

    const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );

    bool show = true;
    ImGui::Begin( "Zone info", &show );

    if( ImGui::Button( "Zoom to zone" ) )
    {
        ZoomToZone( ev );
    }
    ImGui::SameLine();
    if( ImGui::Button( "Go to parent" ) )
    {
        auto parent = GetZoneParent( ev );
        if( parent )
        {
            ShowZoneInfo( *parent );
        }
    }
    ImGui::SameLine();
    if( ImGui::Button( "Statistics" ) )
    {
        m_findZone.ShowZone( ev.srcloc, m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ) );
    }
    if( ev.callstack != 0 )
    {
        ImGui::SameLine();
        bool hilite = m_callstackInfoWindow == ev.callstack;
        if( hilite )
        {
            ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f ) );
        }
        if( ImGui::Button( "Callstack" ) )
        {
            m_callstackInfoWindow = ev.callstack;
        }
        if( hilite )
        {
            ImGui::PopStyleColor( 3 );
        }
    }
    if( !m_zoneInfoStack.empty() )
    {
        ImGui::SameLine();
        if( ImGui::Button( "Go back" ) )
        {
            m_zoneInfoWindow = m_zoneInfoStack.back_and_pop();
        }
    }

    ImGui::Separator();

    const auto tid = GetZoneThread( ev );
    if( ev.name.active )
    {
        TextFocused( "Zone name:", m_worker.GetString( ev.name ) );
    }
    if( srcloc.name.active )
    {
        TextFocused( "Zone name:", m_worker.GetString( srcloc.name ) );
    }
    TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
    ImGui::TextDisabled( "Location:" );
    ImGui::SameLine();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(id)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "0x%" PRIX64, tid );
        ImGui::EndTooltip();
    }
    if( ev.text.active )
    {
        TextFocused( "User text:", m_worker.GetString( ev.text ) );
        dmul++;
    }

    ImGui::Separator();

    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.start;
    TextFocused( "Time from start of program:", TimeToString( ev.start - m_worker.GetFrameBegin( 0 ) ) );
    TextFocused( "Execution time:", TimeToString( ztime ) );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        TextFocused( "Without profiling:", TimeToString( ztime - m_worker.GetDelay() * dmul ) );
        ImGui::EndTooltip();
    }

    auto& mem = m_worker.GetMemData();
    if( mem.plot )
    {
        ImGui::Separator();

        const auto thread = m_worker.CompressThread( tid );

        auto ait = std::lower_bound( mem.data.begin(), mem.data.end(), ev.start, [] ( const auto& l, const auto& r ) { return l.timeAlloc < r; } );
        const auto aend = std::upper_bound( mem.data.begin(), mem.data.end(), end, [] ( const auto& l, const auto& r ) { return l < r.timeAlloc; } );

        auto fit = std::lower_bound( mem.frees.begin(), mem.frees.end(), ev.start, [&mem] ( const auto& l, const auto& r ) { return mem.data[l].timeFree < r; } );
        const auto fend = std::upper_bound( mem.frees.begin(), mem.frees.end(), end, [&mem] ( const auto& l, const auto& r ) { return l < mem.data[r].timeFree; } );

        const auto aDist = std::distance( ait, aend );
        const auto fDist = std::distance( fit, fend );
        if( aDist == 0 && fDist == 0 )
        {
            ImGui::Text( "No memory events." );
        }
        else
        {
            int64_t cAlloc = 0;
            int64_t cFree = 0;
            int64_t nAlloc = 0;
            int64_t nFree = 0;

            auto ait2 = ait;
            auto fit2 = fit;

            while( ait != aend )
            {
                if( ait->threadAlloc == thread )
                {
                    cAlloc += ait->size;
                    nAlloc++;
                }
                ait++;
            }
            while( fit != fend )
            {
                if( mem.data[*fit].threadFree == thread )
                {
                    cFree += mem.data[*fit].size;
                    nFree++;
                }
                fit++;
            }

            if( nAlloc == 0 && nFree == 0 )
            {
                ImGui::Text( "No memory events." );
            }
            else
            {
                ImGui::Text( "%s", RealToString( nAlloc + nFree, true ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "memory events." );
                ImGui::Text( "%s", RealToString( nAlloc, true ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "allocs," );
                ImGui::SameLine();
                ImGui::Text( "%s", RealToString( nFree, true ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "frees." );
                TextFocused( "Memory allocated:", RealToString( cAlloc, true ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "bytes." );
                TextFocused( "Memory freed:", RealToString( cFree, true ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "bytes." );
                TextFocused( "Overall change:", RealToString( cAlloc - cFree, true ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "bytes." );

                if( ImGui::TreeNode( "Allocations list" ) )
                {
                    std::vector<const MemEvent*> v;
                    v.reserve( nAlloc + nFree );

                    auto it = ait2;
                    while( it != aend )
                    {
                        if( it->threadAlloc == thread )
                        {
                            v.emplace_back( it );
                        }
                        it++;
                    }
                    while( fit2 != fend )
                    {
                        const auto ptr = &mem.data[*fit2++];
                        if( ptr->threadFree == thread )
                        {
                            if( ptr < ait2 || ptr >= aend )
                            {
                                v.emplace_back( ptr );
                            }
                        }
                    }
                    pdqsort_branchless( v.begin(), v.end(), [] ( const auto& l, const auto& r ) { return l->timeAlloc < r->timeAlloc; } );

                    ListMemData<decltype( v.begin() )>( v.begin(), v.end(), []( auto& v ) {
                        ImGui::Text( "0x%" PRIx64, (*v)->ptr );
                        return *v;
                    } );
                    ImGui::TreePop();
                }
            }
        }
    }

    ImGui::Separator();

    std::vector<const ZoneEvent*> zoneTrace;
    auto parent = GetZoneParent( ev );
    while( parent )
    {
         zoneTrace.emplace_back( parent );
         parent = GetZoneParent( *parent );
    }
    int idx = 0;
    DrawZoneTrace<const ZoneEvent*>( &ev, zoneTrace, m_worker, [&idx, this] ( const ZoneEvent* v ) {
        const auto& srcloc = m_worker.GetSourceLocation( v->srcloc );
        const auto txt = m_worker.GetZoneName( *v, srcloc );
        ImGui::PushID( idx++ );
        auto sel = ImGui::Selectable( txt, false );
        auto hover = ImGui::IsItemHovered();
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s) %s:%i", TimeToString( m_worker.GetZoneEnd( *v ) - v->start ), m_worker.GetString( srcloc.file ), srcloc.line );
        ImGui::PopID();
        if( sel )
        {
            ShowZoneInfo( *v );
        }
        if( hover )
        {
            m_zoneHighlight = v;
            if( ImGui::IsMouseClicked( 2 ) )
            {
                ZoomToZone( *v );
            }
            ZoneTooltip( *v );
        }
    } );

    if( !ev.child.empty() )
    {
        bool expand = ImGui::TreeNode( "Child zones" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( ev.child.size(), true ) );
        if( expand )
        {
            auto ctt = std::make_unique<uint64_t[]>( ev.child.size() );
            auto cti = std::make_unique<uint32_t[]>( ev.child.size() );
            uint64_t ctime = 0;
            for( size_t i=0; i<ev.child.size(); i++ )
            {
                const auto cend = m_worker.GetZoneEnd( *ev.child[i] );
                const auto ct = cend - ev.child[i]->start;
                ctime += ct;
                ctt[i] = ct;
                cti[i] = uint32_t( i );
            }

            pdqsort_branchless( cti.get(), cti.get() + ev.child.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

            const auto ty = ImGui::GetTextLineHeight();
            ImGui::Columns( 2 );
            ImGui::TextColored( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
            ImGui::NextColumn();
            char buf[128];
            sprintf( buf, "%s (%.2f%%)", TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
            ImGui::ProgressBar( double( ztime - ctime ) / ztime, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
            for( size_t i=0; i<ev.child.size(); i++ )
            {
                auto& cev = *ev.child[cti[i]];
                const auto txt = m_worker.GetZoneName( cev );
                bool b = false;
                ImGui::PushID( (int)i );
                if( ImGui::Selectable( txt, &b, ImGuiSelectableFlags_SpanAllColumns ) )
                {
                    ShowZoneInfo( cev );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_zoneHighlight = &cev;
                    if( ImGui::IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( cev );
                    }
                    ZoneTooltip( cev );
                }
                ImGui::PopID();
                ImGui::NextColumn();
                const auto part = double( ctt[cti[i]] ) / ztime;
                char buf[128];
                sprintf( buf, "%s (%.2f%%)", TimeToString( ctt[cti[i]] ), part * 100 );
                ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                ImGui::NextColumn();
            }
            ImGui::EndColumns();
            ImGui::TreePop();
        }
    }

    ImGui::End();

    if( !show )
    {
        m_zoneInfoWindow = nullptr;
        m_zoneInfoStack.clear();
    }
}

void View::DrawGpuInfoWindow()
{
    auto& ev = *m_gpuInfoWindow;

    bool show = true;
    ImGui::Begin( "Zone info", &show );

    if( ImGui::Button( "Zoom to zone" ) )
    {
        ZoomToZone( ev );
    }
    ImGui::SameLine();
    if( ImGui::Button( "Go to parent" ) )
    {
        auto parent = GetZoneParent( ev );
        if( parent )
        {
            ShowZoneInfo( *parent, m_gpuInfoWindowThread );
        }
    }
    if( ev.callstack != 0 )
    {
        ImGui::SameLine();
        bool hilite = m_callstackInfoWindow == ev.callstack;
        if( hilite )
        {
            ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f ) );
        }
        if( ImGui::Button( "Callstack" ) )
        {
            m_callstackInfoWindow = ev.callstack;
        }
        if( hilite )
        {
            ImGui::PopStyleColor( 3 );
        }
    }
    if( !m_gpuInfoStack.empty() )
    {
        ImGui::SameLine();
        if( ImGui::Button( "Go back" ) )
        {
            m_gpuInfoWindow = m_gpuInfoStack.back_and_pop();
        }
    }

    ImGui::Separator();

    const auto tid = GetZoneThread( ev );
    const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
    TextFocused( "Zone name:", m_worker.GetString( srcloc.name ) );
    TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
    ImGui::TextDisabled( "Location:" );
    ImGui::SameLine();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(id)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "0x%" PRIX64, tid );
        ImGui::EndTooltip();
    }

    ImGui::Separator();

    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.gpuStart;
    TextFocused( "Time from start of program:", TimeToString( ev.gpuStart - m_worker.GetFrameBegin( 0 ) ) );
    TextFocused( "GPU execution time:", TimeToString( ztime ) );
    TextFocused( "CPU command setup time:", TimeToString( ev.cpuEnd - ev.cpuStart ) );
    auto ctx = GetZoneCtx( ev );
    if( !ctx )
    {
        TextFocused( "Delay to execution:", TimeToString( ev.gpuStart - ev.cpuStart ) );
    }
    else
    {
        const auto begin = ctx->timeline.front()->gpuStart;
        const auto drift = GpuDrift( ctx );
        TextFocused( "Delay to execution:", TimeToString( AdjustGpuTime( ev.gpuStart, begin, drift ) - ev.cpuStart ) );
    }

    ImGui::Separator();

    std::vector<const GpuEvent*> zoneTrace;
    auto parent = GetZoneParent( ev );
    while( parent )
    {
        zoneTrace.emplace_back( parent );
        parent = GetZoneParent( *parent );
    }
    int idx = 0;
    DrawZoneTrace<const GpuEvent*>( &ev, zoneTrace, m_worker, [&idx, this] ( const GpuEvent* v ) {
        const auto& srcloc = m_worker.GetSourceLocation( v->srcloc );
        const auto txt = m_worker.GetZoneName( *v, srcloc );
        ImGui::PushID( idx++ );
        auto sel = ImGui::Selectable( txt, false );
        auto hover = ImGui::IsItemHovered();
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s) %s:%i", TimeToString( m_worker.GetZoneEnd( *v ) - v->gpuStart ), m_worker.GetString( srcloc.file ), srcloc.line );
        ImGui::PopID();
        if( sel )
        {
            ShowZoneInfo( *v, m_gpuInfoWindowThread );
        }
        if( hover )
        {
            m_gpuHighlight = v;
            if( ImGui::IsMouseClicked( 2 ) )
            {
                ZoomToZone( *v );
            }
            ZoneTooltip( *v );
        }
    } );

    if( !ev.child.empty() )
    {
        bool expand = ImGui::TreeNode( "Child zones" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( ev.child.size(), true ) );
        if( expand )
        {
            auto ctt = std::make_unique<uint64_t[]>( ev.child.size() );
            auto cti = std::make_unique<uint32_t[]>( ev.child.size() );
            uint64_t ctime = 0;
            for( size_t i=0; i<ev.child.size(); i++ )
            {
                const auto cend = m_worker.GetZoneEnd( *ev.child[i] );
                const auto ct = cend - ev.child[i]->gpuStart;
                ctime += ct;
                ctt[i] = ct;
                cti[i] = uint32_t( i );
            }

            pdqsort_branchless( cti.get(), cti.get() + ev.child.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

            const auto ty = ImGui::GetTextLineHeight();
            ImGui::Columns( 2 );
            ImGui::TextColored( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
            ImGui::NextColumn();
            char buf[128];
            sprintf( buf, "%s (%.2f%%)", TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
            ImGui::ProgressBar( double( ztime - ctime ) / ztime, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
            for( size_t i=0; i<ev.child.size(); i++ )
            {
                auto& cev = *ev.child[cti[i]];
                bool b = false;
                ImGui::PushID( (int)i );
                if( ImGui::Selectable( m_worker.GetZoneName( cev ), &b, ImGuiSelectableFlags_SpanAllColumns ) )
                {
                    ShowZoneInfo( cev, m_gpuInfoWindowThread );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_gpuHighlight = &cev;
                    if( ImGui::IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( cev );
                    }
                    ZoneTooltip( cev );
                }
                ImGui::PopID();
                ImGui::NextColumn();
                const auto part = double( ctt[cti[i]] ) / ztime;
                char buf[128];
                sprintf( buf, "%s (%.2f%%)", TimeToString( ctt[cti[i]] ), part * 100 );
                ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                ImGui::NextColumn();
            }
            ImGui::EndColumns();
            ImGui::TreePop();
        }
    }

    ImGui::End();

    if( !show )
    {
        m_gpuInfoWindow = nullptr;
        m_gpuInfoStack.clear();
    }
}

void View::DrawOptions()
{
    const auto tw = ImGui::GetFontSize();
    ImGui::Begin( "Options", &m_showOptions, ImGuiWindowFlags_AlwaysAutoResize );

    const auto& gpuData = m_worker.GetGpuData();
    if( !gpuData.empty() )
    {
        ImGui::Checkbox( "Draw GPU zones", &m_drawGpuZones );
        const auto expand = ImGui::TreeNode( "GPU zones" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", gpuData.size() );
        if( expand )
        {
            for( size_t i=0; i<gpuData.size(); i++ )
            {
                const bool isVulkan = gpuData[i]->thread == 0;
                char buf[1024];
                if( isVulkan )
                {
                    sprintf( buf, "Vulkan context %zu", i );
                }
                else
                {
                    sprintf( buf, "OpenGL context %zu", i );
                }
                ImGui::Checkbox( buf, &Visible( gpuData[i] ) );
                ImGui::TreePush();
                auto& drift = GpuDrift( gpuData[i] );
                ImGui::InputInt( "Drift (ns/s)", &drift );
                ImGui::TreePop();
            }
            ImGui::TreePop();
        }
    }

    ImGui::Checkbox( "Draw CPU zones", &m_drawZones );
    int ns = (int)m_namespace;
    ImGui::Combo( "Namespaces", &ns, "Full\0Shortened\0None\0" );
    m_namespace = (Namespace)ns;

    if( !m_worker.GetLockMap().empty() )
    {
        ImGui::Separator();
        ImGui::Checkbox( "Draw locks", &m_drawLocks );
        ImGui::SameLine();
        ImGui::Checkbox( "Only contended", &m_onlyContendedLocks );
        const auto expand = ImGui::TreeNode( "Locks" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_worker.GetLockMap().size() );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::Text( "Locks with no recorded events are counted, but not listed." );
            ImGui::EndTooltip();
        }
        if( expand )
        {
            if( ImGui::SmallButton( "Select all" ) )
            {
                for( const auto& l : m_worker.GetLockMap() )
                {
                    Visible( &l.second ) = true;
                }
            }
            ImGui::SameLine();
            if( ImGui::SmallButton( "Unselect all" ) )
            {
                for( const auto& l : m_worker.GetLockMap() )
                {
                    Visible( &l.second ) = false;
                }
            }

            for( const auto& l : m_worker.GetLockMap() )
            {
                if( l.second.valid )
                {
                    char buf[1024];
                    sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( m_worker.GetSourceLocation( l.second.srcloc ).function ) );
                    ImGui::Checkbox( buf, &Visible( &l.second ) );
                }
            }
            ImGui::TreePop();
        }
    }

    if( !m_worker.GetPlots().empty() )
    {
        ImGui::Separator();
        ImGui::Checkbox( "Draw plots", &m_drawPlots );
        const auto expand = ImGui::TreeNode( "Plots" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_worker.GetPlots().size() );
        if( expand )
        {
            for( const auto& p : m_worker.GetPlots() )
            {
                ImGui::Checkbox( GetPlotName( p ), &Visible( p ) );
            }
            ImGui::TreePop();
        }
    }

    ImGui::Separator();
    const auto expand = ImGui::TreeNode( "Visible threads:" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", m_worker.GetThreadData().size() );
    if( expand )
    {
        int idx = 0;
        for( const auto& t : m_worker.GetThreadData() )
        {
            ImGui::PushID( idx++ );
            ImGui::Checkbox( m_worker.GetThreadString( t->id ), &Visible( t ) );
            ImGui::PopID();
        }
        ImGui::TreePop();
    }
    ImGui::End();
}

void View::DrawMessages()
{
    ImGui::Begin( "Messages", &m_showMessages );
    ImGui::Columns( 3 );
    ImGui::Text( "Time" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Click on message to center timeline on it." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Thread" );
    ImGui::NextColumn();
    ImGui::Text( "Message" );
    ImGui::NextColumn();
    ImGui::Separator();

    for( const auto& v : m_worker.GetMessages() )
    {
        ImGui::PushID( v );
        if( ImGui::Selectable( TimeToString( v->time - m_worker.GetFrameBegin( 0 ) ), m_msgHighlight == v, ImGuiSelectableFlags_SpanAllColumns ) )
        {
            CenterAtTime( v->time );
        }
        ImGui::PopID();
        ImGui::NextColumn();
        ImGui::Text( "%s", m_worker.GetThreadString( v->thread ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(0x%" PRIX64 ")", v->thread );
        ImGui::NextColumn();
        ImGui::TextWrapped( "%s", m_worker.GetString( v->ref ) );
        ImGui::NextColumn();
    }
    ImGui::EndColumns();
    ImGui::End();
}

void View::DrawFindZone()
{
    ImGui::Begin( "Find Zone", &m_findZone.show );
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable zone search." );
#else
    if( !m_worker.AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        ImGui::End();
        return;
    }

    ImGui::InputText( "", m_findZone.pattern, 1024 );
    ImGui::SameLine();

    const bool findClicked = ImGui::Button( "Find" );
    ImGui::SameLine();

    if( ImGui::Button( "Clear" ) )
    {
        m_findZone.Reset();
    }

    if( findClicked )
    {
        m_findZone.Reset();
        FindZones();
    }

    if( !m_findZone.match.empty() )
    {
        ImGui::Separator();
        bool expand = ImGui::TreeNodeEx( "Matched source locations", ImGuiTreeNodeFlags_DefaultOpen );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_findZone.match.size() );
        if( expand )
        {
            auto prev = m_findZone.selMatch;
            int idx = 0;
            for( auto& v : m_findZone.match )
            {
                auto& srcloc = m_worker.GetSourceLocation( v );
                auto& zones = m_worker.GetZonesForSourceLocation( v ).zones;
                ImGui::PushID( idx );
                ImGui::RadioButton( m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_findZone.selMatch, idx++ );
                ImGui::SameLine();
                ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s:%i", RealToString( zones.size(), true ), m_worker.GetString( srcloc.file ), srcloc.line );
                ImGui::PopID();
            }
            ImGui::TreePop();

            if( m_findZone.selMatch != prev )
            {
                m_findZone.ResetThreads();
            }
        }

        ImGui::Separator();

        if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
        {
            const auto ty = ImGui::GetFontSize();

            auto& zoneData = m_worker.GetZonesForSourceLocation( m_findZone.match[m_findZone.selMatch] );
            auto& zones = zoneData.zones;
            const auto tmin = zoneData.min;
            const auto tmax = zoneData.max;
            const auto timeTotal = zoneData.total;

            if( tmin != std::numeric_limits<int64_t>::max() )
            {
                ImGui::Checkbox( "Log values", &m_findZone.logVal );
                ImGui::SameLine();
                ImGui::Checkbox( "Log time", &m_findZone.logTime );
                ImGui::SameLine();
                ImGui::Checkbox( "Cumulate time", &m_findZone.cumulateTime );
                ImGui::SameLine();
                ImGui::TextDisabled( "(?)" );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    ImGui::Text( "Show total time taken by calls in each bin instead of call counts." );
                    ImGui::EndTooltip();
                }

                ImGui::TextDisabled( "Time range:" );
                ImGui::SameLine();
                ImGui::Text( "%s - %s (%s)", TimeToString( tmin ), TimeToString( tmax ), TimeToString( tmax - tmin ) );

                const auto dt = double( tmax - tmin );
                const auto selThread = m_findZone.selThread;
                const auto showThreads = m_findZone.showThreads;
                const auto cumulateTime = m_findZone.cumulateTime;

                if( dt > 0 )
                {
                    const auto w = ImGui::GetContentRegionAvail().x;

                    const auto numBins = int64_t( w - 4 );
                    if( numBins > 1 )
                    {
                        if( numBins != m_findZone.numBins )
                        {
                            m_findZone.numBins = numBins;
                            m_findZone.bins = std::make_unique<int64_t[]>( numBins );
                            m_findZone.binTime = std::make_unique<int64_t[]>( numBins );
                            m_findZone.selBin = std::make_unique<int64_t[]>( numBins );
                        }

                        const auto& bins = m_findZone.bins;
                        const auto& binTime = m_findZone.binTime;
                        const auto& selBin = m_findZone.selBin;

                        memset( bins.get(), 0, sizeof( int64_t ) * numBins );
                        memset( binTime.get(), 0, sizeof( int64_t ) * numBins );
                        memset( selBin.get(), 0, sizeof( int64_t ) * numBins );

                        int64_t selBinTime = 0;

                        int64_t selectionTime = 0;
                        if( m_findZone.highlight.active )
                        {
                            const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                            const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );

                            if( selThread != m_findZone.Unselected )
                            {
                                if( m_findZone.logTime )
                                {
                                    const auto tMinLog = log10fast( tmin );
                                    const auto idt = numBins / ( log10fast( tmax ) - tMinLog );
                                    for( auto& ev : zones )
                                    {
                                        const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                        if( timeSpan != 0 )
                                        {
                                            const auto bin = std::min( numBins - 1, int64_t( ( log10fast( timeSpan ) - tMinLog ) * idt ) );
                                            bins[bin]++;
                                            binTime[bin] += timeSpan;
                                            if( selThread == ( showThreads ? ev.thread : ( ev.zone->text.active ? ev.zone->text.idx : std::numeric_limits<uint64_t>::max() ) ) )
                                            {
                                                if( cumulateTime ) selBin[bin] += timeSpan; else selBin[bin]++;
                                                selBinTime += timeSpan;
                                            }
                                            if( timeSpan >= s && timeSpan <= e ) selectionTime += timeSpan;
                                        }
                                    }
                                }
                                else
                                {
                                    const auto idt = numBins / dt;
                                    for( auto& ev : zones )
                                    {
                                        const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                        if( timeSpan != 0 )
                                        {
                                            const auto bin = std::min( numBins - 1, int64_t( ( timeSpan - tmin ) * idt ) );
                                            bins[bin]++;
                                            binTime[bin] += timeSpan;
                                            if( selThread == ( showThreads ? ev.thread : ( ev.zone->text.active ? ev.zone->text.idx : std::numeric_limits<uint64_t>::max() ) ) )
                                            {
                                                if( cumulateTime ) selBin[bin] += timeSpan; else selBin[bin]++;
                                                selBinTime += timeSpan;
                                            }
                                            if( timeSpan >= s && timeSpan <= e ) selectionTime += timeSpan;
                                        }
                                    }
                                }
                            }
                            else
                            {
                                if( m_findZone.logTime )
                                {
                                    const auto tMinLog = log10fast( tmin );
                                    const auto idt = numBins / ( log10fast( tmax ) - tMinLog );
                                    for( auto& ev : zones )
                                    {
                                        const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                        if( timeSpan != 0 )
                                        {
                                            const auto bin = std::min( numBins - 1, int64_t( ( log10fast( timeSpan ) - tMinLog ) * idt ) );
                                            bins[bin]++;
                                            binTime[bin] += timeSpan;
                                            if( timeSpan >= s && timeSpan <= e ) selectionTime += timeSpan;
                                        }
                                    }
                                }
                                else
                                {
                                    const auto idt = numBins / dt;
                                    for( auto& ev : zones )
                                    {
                                        const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                        if( timeSpan != 0 )
                                        {
                                            const auto bin = std::min( numBins - 1, int64_t( ( timeSpan - tmin ) * idt ) );
                                            bins[bin]++;
                                            binTime[bin] += timeSpan;
                                            if( timeSpan >= s && timeSpan <= e ) selectionTime += timeSpan;
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            if( selThread != m_findZone.Unselected )
                            {
                                if( m_findZone.logTime )
                                {
                                    const auto tMinLog = log10fast( tmin );
                                    const auto idt = numBins / ( log10fast( tmax ) - tMinLog );
                                    for( auto& ev : zones )
                                    {
                                        const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                        if( timeSpan != 0 )
                                        {
                                            const auto bin = std::min( numBins - 1, int64_t( ( log10fast( timeSpan ) - tMinLog ) * idt ) );
                                            bins[bin]++;
                                            binTime[bin] += timeSpan;
                                            if( selThread == ( showThreads ? ev.thread : ( ev.zone->text.active ? ev.zone->text.idx : std::numeric_limits<uint64_t>::max() ) ) )
                                            {
                                                if( cumulateTime ) selBin[bin] += timeSpan; else selBin[bin]++;
                                                selBinTime += timeSpan;
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    const auto idt = numBins / dt;
                                    for( auto& ev : zones )
                                    {
                                        const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                        if( timeSpan != 0 )
                                        {
                                            const auto bin = std::min( numBins - 1, int64_t( ( timeSpan - tmin ) * idt ) );
                                            bins[bin]++;
                                            binTime[bin] += timeSpan;
                                            if( selThread == ( showThreads ? ev.thread : ( ev.zone->text.active ? ev.zone->text.idx : std::numeric_limits<uint64_t>::max() ) ) )
                                            {
                                                if( cumulateTime ) selBin[bin] += timeSpan; else selBin[bin]++;
                                                selBinTime += timeSpan;
                                            }
                                        }
                                    }
                                }
                            }
                            else
                            {
                                if( m_findZone.logTime )
                                {
                                    const auto tMinLog = log10fast( tmin );
                                    const auto idt = numBins / ( log10fast( tmax ) - tMinLog );
                                    for( auto& ev : zones )
                                    {
                                        const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                        if( timeSpan != 0 )
                                        {
                                            const auto bin = std::min( numBins - 1, int64_t( ( log10fast( timeSpan ) - tMinLog ) * idt ) );
                                            bins[bin]++;
                                            binTime[bin] += timeSpan;
                                        }
                                    }
                                }
                                else
                                {
                                    const auto idt = numBins / dt;
                                    for( auto& ev : zones )
                                    {
                                        const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                        if( timeSpan != 0 )
                                        {
                                            const auto bin = std::min( numBins - 1, int64_t( ( timeSpan - tmin ) * idt ) );
                                            bins[bin]++;
                                            binTime[bin] += timeSpan;
                                        }
                                    }
                                }
                            }
                        }

                        int64_t maxVal;
                        if( cumulateTime )
                        {
                            maxVal = binTime[0];
                            for( int i=1; i<numBins; i++ )
                            {
                                maxVal = std::max( maxVal, binTime[i] );
                            }
                        }
                        else
                        {
                            maxVal = bins[0];
                            for( int i=1; i<numBins; i++ )
                            {
                                maxVal = std::max( maxVal, bins[i] );
                            }
                        }

                        TextFocused( "Total time:", TimeToString( timeTotal ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextFocused( "Max counts:", cumulateTime ? TimeToString( maxVal ) : RealToString( maxVal, true ) );

                        ImGui::TextDisabled( "Selection range:" );
                        ImGui::SameLine();
                        if( m_findZone.highlight.active )
                        {
                            const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                            const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );
                            ImGui::Text( "%s - %s (%s)", TimeToString( s ), TimeToString( e ), TimeToString( e - s ) );
                        }
                        else
                        {
                            ImGui::Text( "none" );
                        }
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(?)" );
                        if( ImGui::IsItemHovered() )
                        {
                            ImGui::BeginTooltip();
                            ImGui::Text( "Left draw on histogram to select range. Right click to clear selection." );
                            ImGui::EndTooltip();
                        }
                        if( m_findZone.highlight.active )
                        {
                            TextFocused( "Selection time:", TimeToString( selectionTime ) );
                        }
                        else
                        {
                            TextFocused( "Selection time:", "none" );
                        }
                        if( selThread != m_findZone.Unselected )
                        {
                            TextFocused( "Zone group time:", TimeToString( selBinTime ) );
                        }
                        else
                        {
                            TextFocused( "Zone group time:", "none" );
                        }

                        const auto Height = 200 * ImGui::GetTextLineHeight() / 15.f;
                        const auto wpos = ImGui::GetCursorScreenPos();

                        ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 1.5 ) ) );
                        const bool hover = ImGui::IsItemHovered();

                        auto draw = ImGui::GetWindowDrawList();
                        draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x22FFFFFF );
                        draw->AddRect( wpos, wpos + ImVec2( w, Height ), 0x88FFFFFF );

                        if( m_findZone.logVal )
                        {
                            const auto hAdj = double( Height - 4 ) / log10fast( maxVal + 1 );
                            for( int i=0; i<numBins; i++ )
                            {
                                const auto val = cumulateTime ? binTime[i] : bins[i];
                                if( val > 0 )
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - log10fast( val + 1 ) * hAdj ), 0xFF22DDDD );
                                    if( selBin[i] > 0 )
                                    {
                                        draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - log10fast( selBin[i] + 1 ) * hAdj ), 0xFFDD7777 );
                                    }
                                }
                            }
                        }
                        else
                        {
                            const auto hAdj = double( Height - 4 ) / maxVal;
                            for( int i=0; i<numBins; i++ )
                            {
                                const auto val = cumulateTime ? binTime[i] : bins[i];
                                if( val > 0 )
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFF22DDDD );
                                    if( selBin[i] > 0 )
                                    {
                                        draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - selBin[i] * hAdj ), 0xFFDD7777 );
                                    }
                                }
                            }
                        }

                        const auto xoff = 2;
                        const auto yoff = Height + 1;

                        if( m_findZone.logTime )
                        {
                            const auto ltmin = log10fast( tmin );
                            const auto ltmax = log10fast( tmax );
                            const auto start = int( floor( ltmin ) );
                            const auto end = int( ceil( ltmax ) );

                            const auto range = ltmax - ltmin;
                            const auto step = w / range;
                            auto offset = start - ltmin;
                            int tw = 0;
                            int tx = 0;

                            auto tt = int64_t( pow( 10, start ) );

                            static const double logticks[] = { log10( 2 ), log10( 3 ), log10( 4 ), log10( 5 ), log10( 6 ), log10( 7 ), log10( 8 ), log10( 9 ) };

                            for( int i=start; i<=end; i++ )
                            {
                                const auto x = ( i - start + offset ) * step;

                                if( x >= 0 )
                                {
                                    draw->AddLine( wpos + ImVec2( x, yoff ), wpos + ImVec2( x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF );
                                    if( tw == 0 || x > tx + tw + ty * 1.1 )
                                    {
                                        tx = x;
                                        auto txt = TimeToStringInteger( tt );
                                        draw->AddText( wpos + ImVec2( x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                                        tw = ImGui::CalcTextSize( txt ).x;
                                    }
                                }

                                for( int j=0; j<8; j++ )
                                {
                                    const auto xoff = x + logticks[j] * step;
                                    if( xoff >= 0 )
                                    {
                                        draw->AddLine( wpos + ImVec2( xoff, yoff ), wpos + ImVec2( xoff, yoff + round( ty * 0.25 ) ), 0x66FFFFFF );
                                    }
                                }

                                tt *= 10;
                            }
                        }
                        else
                        {
                            const auto pxns = numBins / dt;
                            const auto nspx = 1.0 / pxns;
                            const auto scale = std::max( 0.0f, round( log10fast( nspx ) + 2 ) );
                            const auto step = pow( 10, scale );

                            const auto dx = step * pxns;
                            double x = 0;
                            int tw = 0;
                            int tx = 0;

                            const auto sstep = step / 10.0;
                            const auto sdx = dx / 10.0;

                            static const double linelen[] = { 0.5, 0.25, 0.25, 0.25, 0.25, 0.375, 0.25, 0.25, 0.25, 0.25 };

                            int64_t tt = int64_t( ceil( tmin / sstep ) * sstep );
                            const auto diff = tmin / sstep - int64_t( tmin / sstep );
                            const auto xo = ( diff == 0 ? 0 : ( ( 1 - diff ) * sstep * pxns ) ) + xoff;
                            int iter = int( ceil( ( tmin - int64_t( tmin / step ) * step ) / sstep ) );

                            while( x < numBins )
                            {
                                draw->AddLine( wpos + ImVec2( xo + x, yoff ), wpos + ImVec2( xo + x, yoff + round( ty * linelen[iter] ) ), 0x66FFFFFF );
                                if( iter == 0 && ( tw == 0 || x > tx + tw + ty * 1.1 ) )
                                {
                                    tx = x;
                                    auto txt = TimeToStringInteger( tt );
                                    draw->AddText( wpos + ImVec2( xo + x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                                    tw = ImGui::CalcTextSize( txt ).x;
                                }

                                iter = ( iter + 1 ) % 10;
                                x += sdx;
                                tt += sstep;
                            }
                        }

                        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 2, 2 ), wpos + ImVec2( w-2, Height + round( ty * 1.5 ) ) ) )
                        {
                            const auto ltmin = log10fast( tmin );
                            const auto ltmax = log10fast( tmax );

                            auto& io = ImGui::GetIO();
                            draw->AddLine( ImVec2( io.MousePos.x, wpos.y ), ImVec2( io.MousePos.x, wpos.y+Height-2 ), 0x33FFFFFF );

                            const auto bin = double( io.MousePos.x - wpos.x - 2 );
                            int64_t t0, t1;
                            if( m_findZone.logTime )
                            {
                                t0 = int64_t( pow( 10, ltmin +  bin    / numBins * ( ltmax - ltmin ) ) );

                                // Hackfix for inability to select data in last bin.
                                // A proper solution would be nice.
                                if( bin+1 == numBins )
                                {
                                    t1 = tmax;
                                }
                                else
                                {
                                    t1 = int64_t( pow( 10, ltmin + (bin+1) / numBins * ( ltmax - ltmin ) ) );
                                }
                            }
                            else
                            {
                                t0 = int64_t( tmin +  bin    / numBins * ( tmax - tmin ) );
                                t1 = int64_t( tmin + (bin+1) / numBins * ( tmax - tmin ) );
                            }

                            int64_t tBefore = 0;
                            for( int i=0; i<bin; i++ )
                            {
                                tBefore += binTime[i];
                            }

                            int64_t tAfter = 0;
                            for( int i=bin+1; i<numBins; i++ )
                            {
                                tAfter += binTime[i];
                            }

                            ImGui::BeginTooltip();
                            ImGui::TextDisabled( "Time range:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                            ImGui::TextDisabled( "Count:" );
                            ImGui::SameLine();
                            ImGui::Text( "%" PRIu64, bins[bin] );
                            TextFocused( "Time spent in bin:", TimeToString( binTime[bin] ) );
                            TextFocused( "Time spent in the left bins:", TimeToString( tBefore ) );
                            TextFocused( "Time spent in the right bins:", TimeToString( tAfter ) );
                            ImGui::EndTooltip();

                            if( ImGui::IsMouseClicked( 1 ) )
                            {
                                m_findZone.highlight.active = false;
                                m_findZone.ResetThreads();
                            }
                            else if( ImGui::IsMouseClicked( 0 ) )
                            {
                                m_findZone.highlight.active = true;
                                m_findZone.highlight.start = t0;
                                m_findZone.highlight.end = t1;
                            }
                            else if( ImGui::IsMouseDragging( 0, 0 ) )
                            {
                                m_findZone.highlight.end = t1 > m_findZone.highlight.start ? t1 : t0;
                                m_findZone.ResetThreads();
                            }
                        }

                        if( m_findZone.highlight.active && m_findZone.highlight.start != m_findZone.highlight.end )
                        {
                            const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                            const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );

                            float t0, t1;
                            if( m_findZone.logTime )
                            {
                                const auto ltmin = log10fast( tmin );
                                const auto ltmax = log10fast( tmax );

                                t0 = ( log10fast( s ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                                t1 = ( log10fast( e ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                            }
                            else
                            {
                                t0 = ( s - tmin ) / float( tmax - tmin ) * numBins;
                                t1 = ( e - tmin ) / float( tmax - tmin ) * numBins;
                            }

                            draw->AddRectFilled( wpos + ImVec2( 2 + t0, 1 ), wpos + ImVec2( 2 + t1, Height-1 ), 0x22DD8888 );
                            draw->AddRect( wpos + ImVec2( 2 + t0, 1 ), wpos + ImVec2( 2 + t1, Height-1 ), 0x44DD8888 );
                        }
                    }
                }
            }

            ImGui::TreePop();
        }

        ImGui::Separator();
        ImGui::Text( "Found zones:" );
        ImGui::SameLine();
        if( m_findZone.showThreads )
        {
            if( ImGui::SmallButton( "Group by user text" ) )
            {
                m_findZone.showThreads = false;
                m_findZone.selThread = m_findZone.Unselected;
                m_findZone.ResetThreads();
            }
        }
        else
        {
            if( ImGui::SmallButton( "Group by threads" ) )
            {
                m_findZone.showThreads = true;
                m_findZone.selThread = m_findZone.Unselected;
                m_findZone.ResetThreads();
            }
        }
        ImGui::SameLine();
        if( m_findZone.sortByCounts )
        {
            if( ImGui::SmallButton( "Sort by order" ) )
            {
                m_findZone.sortByCounts = false;
            }
        }
        else
        {
            if( ImGui::SmallButton( "Sort by counts" ) )
            {
                m_findZone.sortByCounts = true;
            }
        }
        ImGui::SameLine();
        ImGui::TextDisabled( "(?)" );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::Text( "Left click to highlight entry. Right click to clear selection." );
            ImGui::EndTooltip();
        }

        auto& zones = m_worker.GetZonesForSourceLocation( m_findZone.match[m_findZone.selMatch] ).zones;
        auto sz = zones.size();
        auto processed = m_findZone.processed;
        const auto hmin = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
        const auto hmax = std::max( m_findZone.highlight.start, m_findZone.highlight.end );
        const auto showThreads = m_findZone.showThreads;
        const auto highlightActive = m_findZone.highlight.active;
        while( processed < sz )
        {
            auto& ev = zones[processed];
            if( ev.zone->end < 0 ) break;

            const auto end = m_worker.GetZoneEndDirect( *ev.zone );
            const auto timespan = end - ev.zone->start;
            if( timespan == 0 )
            {
                processed++;
                continue;
            }

            if( highlightActive )
            {
                if( timespan < hmin || timespan > hmax )
                {
                    processed++;
                    continue;
                }
            }

            processed++;
            if( showThreads )
            {
                m_findZone.threads[ev.thread].push_back( ev.zone );
            }
            else
            {
                const uint64_t id = ev.zone->text.active ? ev.zone->text.idx : std::numeric_limits<uint64_t>::max();
                m_findZone.threads[id].push_back( ev.zone );
            }
        }
        m_findZone.processed = processed;

        Vector<decltype( m_findZone.threads )::iterator> threads;
        threads.reserve_and_use( m_findZone.threads.size() );
        int idx = 0;
        for( auto it = m_findZone.threads.begin(); it != m_findZone.threads.end(); ++it )
        {
            threads[idx++] = it;
        }
        if( m_findZone.sortByCounts )
        {
            pdqsort_branchless( threads.begin(), threads.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.size() > rhs->second.size(); } );
        }

        ImGui::BeginChild( "##zonesScroll", ImVec2( ImGui::GetWindowContentRegionWidth(), std::max( 200.f, ImGui::GetContentRegionAvail().y ) ) );
        for( auto& v : threads )
        {
            const char* hdrString;
            if( showThreads )
            {
                hdrString = m_worker.GetThreadString( m_worker.DecompressThread( v->first ) );
            }
            else
            {
                hdrString = v->first == std::numeric_limits<uint64_t>::max() ? "No user text" : m_worker.GetString( StringIdx( v->first ) );
            }
            ImGui::PushID( v->first );
            const bool expand = ImGui::TreeNodeEx( hdrString, ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick | ( v->first == m_findZone.selThread ? ImGuiTreeNodeFlags_Selected : 0 ) );
            if( ImGui::IsItemClicked() )
            {
                m_findZone.selThread = v->first;
            }
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.5f, 0.5f, 0.5f, 1.0f ), "(%s)", RealToString( v->second.size(), true ) );

            if( expand )
            {
                ImGui::Columns( 3, hdrString );
                ImGui::Separator();
                ImGui::Text( "Time from start" );
                ImGui::NextColumn();
                ImGui::Text( "Execution time" );
                ImGui::NextColumn();
                ImGui::Text( "Name" );
                ImGui::SameLine();
                ImGui::TextDisabled( "(?)" );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    ImGui::Text( "Only displayed if custom zone name is set." );
                    ImGui::EndTooltip();
                }
                ImGui::NextColumn();
                ImGui::Separator();

                for( auto& ev : v->second )
                {
                    const auto end = m_worker.GetZoneEndDirect( *ev );
                    const auto timespan = end - ev->start;

                    ImGui::PushID( ev );
                    if( ImGui::Selectable( TimeToString( ev->start - m_worker.GetFrameBegin( 0 ) ), m_zoneInfoWindow == ev, ImGuiSelectableFlags_SpanAllColumns ) )
                    {
                        ShowZoneInfo( *ev );
                    }
                    if( ImGui::IsItemHovered() )
                    {
                        m_zoneHighlight = ev;
                        if( ImGui::IsMouseClicked( 2 ) )
                        {
                            ZoomToZone( *ev );
                        }
                        ZoneTooltip( *ev );
                    }

                    ImGui::NextColumn();
                    ImGui::Text( "%s", TimeToString( timespan ) );
                    ImGui::NextColumn();
                    if( ev->name.active )
                    {
                        ImGui::Text( "%s", m_worker.GetString( ev->name ) );
                    }
                    ImGui::NextColumn();

                    ImGui::PopID();
                }
                ImGui::Columns( 1 );
                ImGui::Separator();
                ImGui::TreePop();
            }
        }
        ImGui::EndChild();
        if( ImGui::IsItemHovered() && ImGui::IsMouseClicked( 1 ) )
        {
            m_findZone.selThread = m_findZone.Unselected;
        }
    }
#endif

    ImGui::End();
}

void View::DrawCompare()
{
    ImGui::Begin( "Compare traces", &m_compare.show );
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable trace comparison." );
#elif !defined TRACY_FILESELECTOR
    ImGui::TextWrapped( "File selector is disabled in this build." );
    ImGui::TextWrapped( "Rebuild with the TRACY_FILESELECTOR macro to enable trace comparison." );
#else
    if( !m_compare.second )
    {
        ImGui::TextWrapped( "Please load a second trace to compare results." );
        if( ImGui::Button( "Open second trace" ) )
        {
            nfdchar_t* fn;
            auto res = NFD_OpenDialog( "tracy", nullptr, &fn );
            if( res == NFD_OKAY )
            {
                try
                {
                    auto f = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( fn ) );
                    if( f )
                    {
                        m_compare.second = std::make_unique<Worker>( *f, EventType::None );
                    }
                }
                catch( const tracy::UnsupportedVersion& e )
                {
                    m_compare.badVer = e.version;
                }
                catch( const tracy::NotTracyDump& e )
                {
                    m_compare.badVer = -1;
                }
            }
        }
        tracy::BadVersion( m_compare.badVer );
        ImGui::End();
        return;
    }

    if( !m_worker.AreSourceLocationZonesReady() || !m_compare.second->AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        ImGui::End();
        return;
    }

    ImGui::TextDisabled( "This trace:" );
    ImGui::SameLine();
    ImGui::Text( "%s", m_worker.GetCaptureName().c_str() );

    ImGui::TextDisabled( "External trace:" );
    ImGui::SameLine();
    ImGui::Text( "%s", m_compare.second->GetCaptureName().c_str() );
    ImGui::SameLine();
    if( ImGui::SmallButton( "Unload" ) )
    {
        m_compare.Reset();
        m_compare.second.reset();
        ImGui::End();
        return;
    }

    ImGui::InputText( "", m_compare.pattern, 1024 );
    ImGui::SameLine();

    const bool findClicked = ImGui::Button( "Find" );
    ImGui::SameLine();

    if( ImGui::Button( "Clear" ) )
    {
        m_compare.Reset();
    }

    if( findClicked )
    {
        m_compare.Reset();
        FindZonesCompare();
    }

    if( m_compare.match[0].empty() && m_compare.match[1].empty() )
    {
        ImGui::End();
        return;
    }

    if( ImGui::TreeNodeEx( "Matched source locations", ImGuiTreeNodeFlags_DefaultOpen ) )
    {
        ImGui::Separator();
        ImGui::Columns( 2 );
        ImGui::Text( "This capture" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_compare.match[0].size() );
        ImGui::NextColumn();
        ImGui::Text( "External capture" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_compare.match[1].size() );
        ImGui::Separator();
        ImGui::NextColumn();

        auto prev = m_compare.selMatch[0];
        int idx = 0;
        for( auto& v : m_compare.match[0] )
        {
            auto& srcloc = m_worker.GetSourceLocation( v );
            auto& zones = m_worker.GetZonesForSourceLocation( v ).zones;
            ImGui::PushID( idx );
            ImGui::RadioButton( m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_compare.selMatch[0], idx++ );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s:%i", RealToString( zones.size(), true ), m_worker.GetString( srcloc.file ), srcloc.line );
            ImGui::PopID();
        }
        ImGui::NextColumn();

        prev = m_compare.selMatch[1];
        idx = 0;
        for( auto& v : m_compare.match[1] )
        {
            auto& srcloc = m_compare.second->GetSourceLocation( v );
            auto& zones = m_compare.second->GetZonesForSourceLocation( v ).zones;
            ImGui::PushID( -1 - idx );
            ImGui::RadioButton( m_compare.second->GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_compare.selMatch[1], idx++ );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s:%i", RealToString( zones.size(), true ), m_compare.second->GetString( srcloc.file ), srcloc.line );
            ImGui::PopID();
        }
        ImGui::NextColumn();

        ImGui::EndColumns();
        ImGui::TreePop();
    }

    ImGui::Separator();

    if( m_compare.match[0].empty() || m_compare.match[1].empty() )
    {
        ImGui::TextWrapped( "Both traces must have matches." );
        ImGui::End();
        return;
    }

    if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
    {
        const auto ty = ImGui::GetFontSize();

        auto& zoneData0 = m_worker.GetZonesForSourceLocation( m_compare.match[0][m_compare.selMatch[0]] );
        auto& zoneData1 = m_compare.second->GetZonesForSourceLocation( m_compare.match[1][m_compare.selMatch[1]] );
        auto& zones0 = zoneData0.zones;
        auto& zones1 = zoneData1.zones;

        auto tmin = std::min( zoneData0.min, zoneData1.min );
        auto tmax = std::max( zoneData0.max, zoneData1.max );;

        if( tmin != std::numeric_limits<int64_t>::max() )
        {
            ImGui::Checkbox( "Log values", &m_compare.logVal );
            ImGui::SameLine();
            ImGui::Checkbox( "Log time", &m_compare.logTime );
            ImGui::SameLine();
            ImGui::Checkbox( "Cumulate time", &m_compare.cumulateTime );
            ImGui::SameLine();
            ImGui::TextDisabled( "(?)" );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "Show total time taken by calls in each bin instead of call counts." );
                ImGui::EndTooltip();
            }
            ImGui::SameLine();
            ImGui::Checkbox( "Normalize values", &m_compare.normalize );
            ImGui::SameLine();
            ImGui::TextDisabled( "(?)" );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "Normalization will fudge reported data values!" );
                ImGui::EndTooltip();
            }

            ImGui::TextDisabled( "Time range:" );
            ImGui::SameLine();
            ImGui::Text( "%s - %s (%s)", TimeToString( tmin ), TimeToString( tmax ), TimeToString( tmax - tmin ) );

            const auto dt = double( tmax - tmin );
            const auto cumulateTime = m_compare.cumulateTime;

            if( dt > 0 )
            {
                const auto w = ImGui::GetContentRegionAvail().x;

                const auto numBins = int64_t( w - 4 );
                if( numBins > 1 )
                {
                    if( numBins != m_compare.numBins )
                    {
                        m_compare.numBins = numBins;
                        m_compare.bins = std::make_unique<CompVal[]>( numBins );
                        m_compare.binTime = std::make_unique<CompVal[]>( numBins );
                    }

                    const auto& bins = m_compare.bins;
                    const auto& binTime = m_compare.binTime;

                    memset( bins.get(), 0, sizeof( CompVal ) * numBins );
                    memset( binTime.get(), 0, sizeof( CompVal ) * numBins );

                    double adj0 = 1;
                    double adj1 = 1;
                    if( m_compare.normalize )
                    {
                        if( zones0.size() > zones1.size() )
                        {
                            adj1 = double( zones0.size() ) / zones1.size();
                        }
                        else
                        {
                            adj0 = double( zones1.size() ) / zones0.size();
                        }

                        if( m_compare.logTime )
                        {
                            const auto tMinLog = log10fast( tmin );
                            const auto idt = numBins / ( log10fast( tmax ) - tMinLog );
                            for( auto& ev : zones0 )
                            {
                                const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                if( timeSpan != 0 )
                                {
                                    const auto bin = std::min( numBins - 1, int64_t( ( log10fast( timeSpan ) - tMinLog ) * idt ) );
                                    bins[bin].v0 += adj0;
                                    binTime[bin].v0 += timeSpan * adj0;
                                }
                            }
                            for( auto& ev : zones1 )
                            {
                                const auto timeSpan = m_compare.second->GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                if( timeSpan != 0 )
                                {
                                    const auto bin = std::min( numBins - 1, int64_t( ( log10fast( timeSpan ) - tMinLog ) * idt ) );
                                    bins[bin].v1 += adj1;
                                    binTime[bin].v1 += timeSpan * adj1;
                                }
                            }
                        }
                        else
                        {
                            const auto idt = numBins / dt;
                            for( auto& ev : zones0 )
                            {
                                const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                if( timeSpan != 0 )
                                {
                                    const auto bin = std::min( numBins - 1, int64_t( ( timeSpan - tmin ) * idt ) );
                                    bins[bin].v0 += adj0;
                                    binTime[bin].v0 += timeSpan * adj0;
                                }
                            }
                            for( auto& ev : zones1 )
                            {
                                const auto timeSpan = m_compare.second->GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                if( timeSpan != 0 )
                                {
                                    const auto bin = std::min( numBins - 1, int64_t( ( timeSpan - tmin ) * idt ) );
                                    bins[bin].v1 += adj1;
                                    binTime[bin].v1 += timeSpan * adj1;
                                }
                            }
                        }
                    }
                    else
                    {
                        if( m_compare.logTime )
                        {
                            const auto tMinLog = log10fast( tmin );
                            const auto idt = numBins / ( log10fast( tmax ) - tMinLog );
                            for( auto& ev : zones0 )
                            {
                                const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                if( timeSpan != 0 )
                                {
                                    const auto bin = std::min( numBins - 1, int64_t( ( log10fast( timeSpan ) - tMinLog ) * idt ) );
                                    bins[bin].v0++;
                                    binTime[bin].v0 += timeSpan;
                                }
                            }
                            for( auto& ev : zones1 )
                            {
                                const auto timeSpan = m_compare.second->GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                if( timeSpan != 0 )
                                {
                                    const auto bin = std::min( numBins - 1, int64_t( ( log10fast( timeSpan ) - tMinLog ) * idt ) );
                                    bins[bin].v1++;
                                    binTime[bin].v1 += timeSpan;
                                }
                            }
                        }
                        else
                        {
                            const auto idt = numBins / dt;
                            for( auto& ev : zones0 )
                            {
                                const auto timeSpan = m_worker.GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                if( timeSpan != 0 )
                                {
                                    const auto bin = std::min( numBins - 1, int64_t( ( timeSpan - tmin ) * idt ) );
                                    bins[bin].v0++;
                                    binTime[bin].v0 += timeSpan;
                                }
                            }
                            for( auto& ev : zones1 )
                            {
                                const auto timeSpan = m_compare.second->GetZoneEndDirect( *ev.zone ) - ev.zone->start;
                                if( timeSpan != 0 )
                                {
                                    const auto bin = std::min( numBins - 1, int64_t( ( timeSpan - tmin ) * idt ) );
                                    bins[bin].v1++;
                                    binTime[bin].v1 += timeSpan;
                                }
                            }
                        }
                    }

                    double maxVal;
                    if( cumulateTime )
                    {
                        maxVal = std::max( binTime[0].v0, binTime[0].v1 );
                        for( int i=1; i<numBins; i++ )
                        {
                            maxVal = std::max( { maxVal, binTime[i].v0, binTime[i].v1 } );
                        }
                    }
                    else
                    {
                        maxVal = std::max( bins[0].v0, bins[0].v1 );
                        for( int i=1; i<numBins; i++ )
                        {
                            maxVal = std::max( { maxVal, bins[i].v0, bins[i].v1 } );
                        }
                    }

                    TextFocused( "Total time (this):", TimeToString( zoneData0.total * adj0 ) );
                    TextFocused( "Total time (external):", TimeToString( zoneData1.total * adj1 ) );
                    TextFocused( "Max counts:", cumulateTime ? TimeToString( maxVal ) : RealToString( floor( maxVal ), true ) );

                    ImGui::ColorButton( "c1", ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                    ImGui::SameLine();
                    ImGui::Text( "This trace" );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();

                    ImGui::ColorButton( "c2", ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                    ImGui::SameLine();
                    ImGui::Text( "External trace" );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();

                    ImGui::ColorButton( "c3", ImVec4( 0x44/255.f, 0xBB/255.f, 0xBB/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                    ImGui::SameLine();
                    ImGui::Text( "Overlap" );

                    const auto Height = 200 * ImGui::GetTextLineHeight() / 15.f;
                    const auto wpos = ImGui::GetCursorScreenPos();

                    ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 1.5 ) ) );
                    const bool hover = ImGui::IsItemHovered();

                    auto draw = ImGui::GetWindowDrawList();
                    draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x22FFFFFF );
                    draw->AddRect( wpos, wpos + ImVec2( w, Height ), 0x88FFFFFF );

                    if( m_compare.logVal )
                    {
                        const auto hAdj = double( Height - 4 ) / log10fast( maxVal + 1 );
                        for( int i=0; i<numBins; i++ )
                        {
                            const auto val0 = cumulateTime ? binTime[i].v0 : bins[i].v0;
                            const auto val1 = cumulateTime ? binTime[i].v1 : bins[i].v1;
                            if( val0 > 0 || val1 > 0 )
                            {
                                const auto val = std::min( val0, val1 );
                                if( val > 0 )
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - log10fast( val + 1 ) * hAdj ), 0xFFBBBB44 );
                                }
                                if( val1 == val )
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 - log10fast( val + 1 ) * hAdj ), wpos + ImVec2( 2+i, Height-3 - log10fast( val0 + 1 ) * hAdj ), 0xFF22DDDD );
                                }
                                else
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 - log10fast( val + 1 ) * hAdj ), wpos + ImVec2( 2+i, Height-3 - log10fast( val1 + 1 ) * hAdj ), 0xFF2222DD );
                                }
                            }
                        }
                    }
                    else
                    {
                        const auto hAdj = double( Height - 4 ) / maxVal;
                        for( int i=0; i<numBins; i++ )
                        {
                            const auto val0 = cumulateTime ? binTime[i].v0 : bins[i].v0;
                            const auto val1 = cumulateTime ? binTime[i].v1 : bins[i].v1;
                            if( val0 > 0 || val1 > 0 )
                            {
                                const auto val = std::min( val0, val1 );
                                if( val > 0 )
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFFBBBB44 );
                                }
                                if( val1 == val )
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 - val * hAdj ), wpos + ImVec2( 2+i, Height-3 - val0 * hAdj ), 0xFF22DDDD );
                                }
                                else
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 - val * hAdj ), wpos + ImVec2( 2+i, Height-3 - val1 * hAdj ), 0xFF2222DD );
                                }
                            }
                        }
                    }

                    const auto xoff = 2;
                    const auto yoff = Height + 1;

                    if( m_compare.logTime )
                    {
                        const auto ltmin = log10fast( tmin );
                        const auto ltmax = log10fast( tmax );
                        const auto start = int( floor( ltmin ) );
                        const auto end = int( ceil( ltmax ) );

                        const auto range = ltmax - ltmin;
                        const auto step = w / range;
                        auto offset = start - ltmin;
                        int tw = 0;
                        int tx = 0;

                        auto tt = int64_t( pow( 10, start ) );

                        static const double logticks[] = { log10( 2 ), log10( 3 ), log10( 4 ), log10( 5 ), log10( 6 ), log10( 7 ), log10( 8 ), log10( 9 ) };

                        for( int i=start; i<=end; i++ )
                        {
                            const auto x = ( i - start + offset ) * step;

                            if( x >= 0 )
                            {
                                draw->AddLine( wpos + ImVec2( x, yoff ), wpos + ImVec2( x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF );
                                if( tw == 0 || x > tx + tw + ty * 1.1 )
                                {
                                    tx = x;
                                    auto txt = TimeToStringInteger( tt );
                                    draw->AddText( wpos + ImVec2( x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                                    tw = ImGui::CalcTextSize( txt ).x;
                                }
                            }

                            for( int j=0; j<8; j++ )
                            {
                                const auto xoff = x + logticks[j] * step;
                                if( xoff >= 0 )
                                {
                                    draw->AddLine( wpos + ImVec2( xoff, yoff ), wpos + ImVec2( xoff, yoff + round( ty * 0.25 ) ), 0x66FFFFFF );
                                }
                            }

                            tt *= 10;
                        }
                    }
                    else
                    {
                        const auto pxns = numBins / dt;
                        const auto nspx = 1.0 / pxns;
                        const auto scale = std::max( 0.0f, round( log10fast( nspx ) + 2 ) );
                        const auto step = pow( 10, scale );

                        const auto dx = step * pxns;
                        double x = 0;
                        int tw = 0;
                        int tx = 0;

                        const auto sstep = step / 10.0;
                        const auto sdx = dx / 10.0;

                        static const double linelen[] = { 0.5, 0.25, 0.25, 0.25, 0.25, 0.375, 0.25, 0.25, 0.25, 0.25 };

                        int64_t tt = int64_t( ceil( tmin / sstep ) * sstep );
                        const auto diff = tmin / sstep - int64_t( tmin / sstep );
                        const auto xo = ( diff == 0 ? 0 : ( ( 1 - diff ) * sstep * pxns ) ) + xoff;
                        int iter = int( ceil( ( tmin - int64_t( tmin / step ) * step ) / sstep ) );

                        while( x < numBins )
                        {
                            draw->AddLine( wpos + ImVec2( xo + x, yoff ), wpos + ImVec2( xo + x, yoff + round( ty * linelen[iter] ) ), 0x66FFFFFF );
                            if( iter == 0 && ( tw == 0 || x > tx + tw + ty * 1.1 ) )
                            {
                                tx = x;
                                auto txt = TimeToStringInteger( tt );
                                draw->AddText( wpos + ImVec2( xo + x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                                tw = ImGui::CalcTextSize( txt ).x;
                            }

                            iter = ( iter + 1 ) % 10;
                            x += sdx;
                            tt += sstep;
                        }
                    }

                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 2, 2 ), wpos + ImVec2( w-2, Height + round( ty * 1.5 ) ) ) )
                    {
                        const auto ltmin = log10fast( tmin );
                        const auto ltmax = log10fast( tmax );

                        auto& io = ImGui::GetIO();
                        draw->AddLine( ImVec2( io.MousePos.x, wpos.y ), ImVec2( io.MousePos.x, wpos.y+Height-2 ), 0x33FFFFFF );

                        const auto bin = double( io.MousePos.x - wpos.x - 2 );
                        int64_t t0, t1;
                        if( m_compare.logTime )
                        {
                            t0 = int64_t( pow( 10, ltmin +  bin    / numBins * ( ltmax - ltmin ) ) );
                            t1 = int64_t( pow( 10, ltmin + (bin+1) / numBins * ( ltmax - ltmin ) ) );
                        }
                        else
                        {
                            t0 = int64_t( tmin +  bin    / numBins * ( tmax - tmin ) );
                            t1 = int64_t( tmin + (bin+1) / numBins * ( tmax - tmin ) );
                        }

                        int64_t tBefore[2] = { 0, 0 };
                        for( int i=0; i<bin; i++ )
                        {
                            tBefore[0] += binTime[i].v0;
                            tBefore[1] += binTime[i].v1;
                        }

                        int64_t tAfter[2] = { 0, 0 };
                        for( int i=bin+1; i<numBins; i++ )
                        {
                            tAfter[0] += binTime[i].v0;
                            tAfter[1] += binTime[i].v1;
                        }

                        ImGui::BeginTooltip();
                        ImGui::TextDisabled( "Time range:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                        ImGui::TextDisabled( "Count:" );
                        ImGui::SameLine();
                        ImGui::Text( "%g / %g", floor( bins[bin].v0 ), floor( bins[bin].v1 ) );
                        ImGui::TextDisabled( "Time spent in bin:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", TimeToString( binTime[bin].v0 ), TimeToString( binTime[bin].v1 ) );
                        ImGui::TextDisabled( "Time spent in the left bins:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", TimeToString( tBefore[0] ), TimeToString( tBefore[1] ) );
                        ImGui::TextDisabled( "Time spent in the right bins:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", TimeToString( tAfter[0] ), TimeToString( tAfter[1] ) );
                        ImGui::TextDisabled( "(Data is displayed as: [this trace] / [external trace])" );
                        ImGui::EndTooltip();
                    }
                }
            }
        }
        ImGui::TreePop();
    }

#endif
    ImGui::End();
}

void View::DrawStatistics()
{
    ImGui::Begin( "Statistics", &m_showStatistics );
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable statistics view." );
#else
    if( !m_worker.AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        ImGui::End();
        return;
    }

    ImGui::Checkbox( "Show self times", &m_statSelf );

    auto& slz = m_worker.GetSourceLocationZones();
    Vector<decltype(slz.begin())> srcloc;
    srcloc.reserve( slz.size() );
    for( auto it = slz.begin(); it != slz.end(); ++it )
    {
        if( it->second.total != 0 )
        {
            srcloc.push_back_no_space_check( it );
        }
    }

    switch( m_statSort )
    {
    case 0:
        if( m_statSelf )
        {
            pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.selfTotal > rhs->second.selfTotal; } );
        }
        else
        {
            pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.total > rhs->second.total; } );
        }
        break;
    case 1:
        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.zones.size() > rhs->second.zones.size(); } );
        break;
    case 2:
        if( m_statSelf )
        {
            pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.selfTotal / lhs->second.zones.size() > rhs->second.selfTotal / rhs->second.zones.size(); } );
        }
        else
        {
            pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.total / lhs->second.zones.size() > rhs->second.total / rhs->second.zones.size(); } );
        }
        break;
    default:
        assert( false );
        break;
    }

    ImGui::Text( "Recorded source locations: %s", RealToString( srcloc.size(), true ) );

    ImGui::Columns( 5 );
    ImGui::Separator();
    ImGui::Text( "Name" );
    ImGui::NextColumn();
    ImGui::Text( "Location" );
    ImGui::NextColumn();
    if( ImGui::SmallButton( "Total time" ) ) m_statSort = 0;
    ImGui::NextColumn();
    if( ImGui::SmallButton( "Counts" ) ) m_statSort = 1;
    ImGui::NextColumn();
    if( ImGui::SmallButton( "MTPC" ) ) m_statSort = 2;
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Mean time per call" );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Separator();

    for( auto& v : srcloc )
    {
        ImGui::PushID( v->first );

        auto& srcloc = m_worker.GetSourceLocation( v->first );
        auto name = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
        if( ImGui::Selectable( name, m_findZone.show && !m_findZone.match.empty() && m_findZone.match[m_findZone.selMatch] == v->first, ImGuiSelectableFlags_SpanAllColumns ) )
        {
            m_findZone.ShowZone( v->first, name );
        }
        ImGui::NextColumn();
        ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
        ImGui::NextColumn();
        ImGui::Text( "%s", TimeToString( m_statSelf ? v->second.selfTotal : v->second.total ) );
        ImGui::NextColumn();
        ImGui::Text( "%s", RealToString( v->second.zones.size(), true ) );
        ImGui::NextColumn();
        ImGui::Text( "%s", TimeToString( ( m_statSelf ? v->second.selfTotal : v->second.total ) / v->second.zones.size() ) );
        ImGui::NextColumn();

        ImGui::PopID();
    }
    ImGui::EndColumns();
#endif
    ImGui::End();
}

void View::DrawCallstackWindow()
{
    bool show = true;
    ImGui::Begin( "Callstack", &show );

    auto& cs = m_worker.GetCallstack( m_callstackInfoWindow );

    ImGui::Columns( 3 );
    ImGui::Text( "Frame" );
    ImGui::NextColumn();
    ImGui::Text( "Function" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Click on entry to copy it to clipboard." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Location" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Click on entry to copy it to clipboard." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();

    int fidx = 0;
    for( auto& entry : cs )
    {
        ImGui::Separator();
        ImGui::Text( "%i", fidx++ );
        ImGui::NextColumn();

        auto frame = m_worker.GetCallstackFrame( entry );
        if( !frame )
        {
            char buf[32];
            sprintf( buf, "%p", (void*)entry );
            ImGui::Text( "%s", buf );
            if( ImGui::IsItemClicked() )
            {
                ImGui::SetClipboardText( buf );
            }
            ImGui::NextColumn();
            ImGui::NextColumn();
        }
        else
        {
            auto txt = m_worker.GetString( frame->name );
            ImGui::TextWrapped( "%s", txt );
            if( ImGui::IsItemClicked() )
            {
                ImGui::SetClipboardText( txt );
            }
            ImGui::NextColumn();
            ImGui::PushTextWrapPos( 0.0f );
            txt = m_worker.GetString( frame->file );
            if( frame->line == 0 )
            {
                ImGui::TextDisabled( "%s", txt );
            }
            else
            {
                ImGui::TextDisabled( "%s:%i", txt, frame->line );
            }
            if( ImGui::IsItemClicked() )
            {
                ImGui::SetClipboardText( txt );
            }
            ImGui::PopTextWrapPos();
            ImGui::NextColumn();
        }
    }

    ImGui::EndColumns();
    ImGui::End();

    if( !show )
    {
        m_callstackInfoWindow = 0;
    }
}

template<class T>
void View::ListMemData( T ptr, T end, std::function<const MemEvent*(T&)> DrawAddress, const char* id )
{
    const auto& style = ImGui::GetStyle();
    const auto dist = std::distance( ptr, end ) + 1;
    const auto ty = ImGui::GetTextLineHeight() + style.ItemSpacing.y;

    ImGui::BeginChild( id ? id : "##memScroll", ImVec2( 0, std::max( ty * std::min<int64_t>( dist, 5 ), std::min( ty * dist, ImGui::GetContentRegionAvail().y ) ) ) );
    ImGui::Columns( 8 );
    ImGui::Text( "Address" );
    ImGui::NextColumn();
    ImGui::Text( "Size" );
    ImGui::NextColumn();
    ImGui::Text( "Appeared at" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Click on entry to center timeline at the memory allocation time." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Duration" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Active allocations are displayed using green color." );
        ImGui::Text( "Click on entry to center timeline at the memory release time." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Thread" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Shows one thread if alloc and free was performed on the same thread." );
        ImGui::Text( "Otherwise two threads are displayed in order: alloc, free." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Zone alloc" );
    ImGui::NextColumn();
    ImGui::Text( "Zone free" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "If alloc and free is performed in the same zone, it is displayed in yellow color." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Callstack" );
    ImGui::NextColumn();
    ImGui::Separator();
    int idx = 0;
    while( ptr != end )
    {
        auto v = DrawAddress( ptr );
        ImGui::NextColumn();
        ImGui::Text( "%s", RealToString( v->size, true ) );
        ImGui::NextColumn();
        ImGui::PushID( idx++ );
        if( ImGui::Selectable( TimeToString( v->timeAlloc - m_worker.GetFrameBegin( 0 ) ) ) )
        {
            CenterAtTime( v->timeAlloc );
        }
        ImGui::PopID();
        ImGui::NextColumn();
        if( v->timeFree < 0 )
        {
            ImGui::TextColored( ImVec4( 0.6f, 1.f, 0.6f, 1.f ), "%s", TimeToString( m_worker.GetLastTime() - v->timeAlloc ) );
            ImGui::NextColumn();
            ImGui::Text( "%s", m_worker.GetThreadString( m_worker.DecompressThread( v->threadAlloc ) ) );
        }
        else
        {
            ImGui::PushID( idx++ );
            if( ImGui::Selectable( TimeToString( v->timeFree - v->timeAlloc ) ) )
            {
                CenterAtTime( v->timeFree );
            }
            ImGui::PopID();
            ImGui::NextColumn();
            if( v->threadAlloc == v->threadFree )
            {
                ImGui::Text( "%s", m_worker.GetThreadString( m_worker.DecompressThread( v->threadAlloc ) ) );
            }
            else
            {
                ImGui::Text( "%s / %s", m_worker.GetThreadString( m_worker.DecompressThread( v->threadAlloc ) ), m_worker.GetThreadString( m_worker.DecompressThread( v->threadFree ) ) );
            }
        }
        ImGui::NextColumn();
        auto zone = FindZoneAtTime( m_worker.DecompressThread( v->threadAlloc ), v->timeAlloc );
        if( !zone )
        {
            ImGui::Text( "-" );
        }
        else
        {
            const auto& srcloc = m_worker.GetSourceLocation( zone->srcloc );
            const auto txt = srcloc.name.active ? m_worker.GetString( srcloc.name ) : m_worker.GetString( srcloc.function );
            ImGui::PushID( idx++ );
            auto sel = ImGui::Selectable( txt, m_zoneInfoWindow == zone );
            auto hover = ImGui::IsItemHovered();
            ImGui::PopID();
            if( sel )
            {
                ShowZoneInfo( *zone );
            }
            if( hover )
            {
                m_zoneHighlight = zone;
                if( ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *zone );
                }
                ZoneTooltip( *zone );
            }
        }
        ImGui::NextColumn();
        if( v->timeFree < 0 )
        {
            ImGui::TextColored( ImVec4( 0.6f, 1.f, 0.6f, 1.f ), "active" );
        }
        else
        {
            auto zoneFree = FindZoneAtTime( m_worker.DecompressThread( v->threadFree ), v->timeFree );
            if( !zoneFree )
            {
                ImGui::Text( "-" );
            }
            else
            {
                const auto& srcloc = m_worker.GetSourceLocation( zoneFree->srcloc );
                const auto txt = srcloc.name.active ? m_worker.GetString( srcloc.name ) : m_worker.GetString( srcloc.function );
                ImGui::PushID( idx++ );
                bool sel;
                if( zoneFree == zone )
                {
                    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 1.f, 0.6f, 1.f ) );
                    sel = ImGui::Selectable( txt, m_zoneInfoWindow == zoneFree );
                    ImGui::PopStyleColor( 1 );
                }
                else
                {
                    sel = ImGui::Selectable( txt, m_zoneInfoWindow == zoneFree );
                }
                auto hover = ImGui::IsItemHovered();
                ImGui::PopID();
                if( sel )
                {
                    ShowZoneInfo( *zoneFree );
                }
                if( hover )
                {
                    m_zoneHighlight = zoneFree;
                    if( ImGui::IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( *zoneFree );
                    }
                    ZoneTooltip( *zoneFree );
                }
            }
        }
        ImGui::NextColumn();
        if( v->csAlloc == 0 )
        {
            ImGui::TextDisabled( "[alloc]" );
        }
        else
        {
            bool hilite = m_callstackInfoWindow == v->csAlloc;
            if( hilite )
            {
                ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f ) );
                ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f ) );
                ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f ) );
            }
            ImGui::PushID( idx++ );
            if( ImGui::SmallButton( "alloc" ) )
            {
                m_callstackInfoWindow = v->csAlloc;
            }
            ImGui::PopID();
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
            if( ImGui::IsItemHovered() )
            {
                CallstackTooltip( v->csAlloc );
            }
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( v->csFree == 0 )
        {
            ImGui::TextDisabled( "[free]" );
        }
        else
        {
            bool hilite = m_callstackInfoWindow == v->csFree;
            if( hilite )
            {
                ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f ) );
                ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f ) );
                ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f ) );
            }
            ImGui::PushID( idx++ );
            if( ImGui::SmallButton( "free" ) )
            {
                m_callstackInfoWindow = v->csFree;
            }
            ImGui::PopID();
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
            if( ImGui::IsItemHovered() )
            {
                CallstackTooltip( v->csFree );
            }
        }
        ImGui::NextColumn();
        ptr++;
    }
    ImGui::EndColumns();
    ImGui::EndChild();
}

enum { ChunkBits = 10 };
enum { PageBits = 10 };
enum { PageSize = 1 << PageBits };
enum { PageChunkBits = ChunkBits + PageBits };
enum { PageChunkSize = 1 << PageChunkBits };

uint32_t MemDecayColor[256] = {
    0x0, 0xFF077F07, 0xFF078007, 0xFF078207, 0xFF078307, 0xFF078507, 0xFF078707, 0xFF078807,
    0xFF078A07, 0xFF078B07, 0xFF078D07, 0xFF078F07, 0xFF079007, 0xFF089208, 0xFF089308, 0xFF089508,
    0xFF089708, 0xFF089808, 0xFF089A08, 0xFF089B08, 0xFF089D08, 0xFF089F08, 0xFF08A008, 0xFF08A208,
    0xFF09A309, 0xFF09A509, 0xFF09A709, 0xFF09A809, 0xFF09AA09, 0xFF09AB09, 0xFF09AD09, 0xFF09AF09,
    0xFF09B009, 0xFF09B209, 0xFF09B309, 0xFF09B509, 0xFF0AB70A, 0xFF0AB80A, 0xFF0ABA0A, 0xFF0ABB0A,
    0xFF0ABD0A, 0xFF0ABF0A, 0xFF0AC00A, 0xFF0AC20A, 0xFF0AC30A, 0xFF0AC50A, 0xFF0AC70A, 0xFF0BC80B,
    0xFF0BCA0B, 0xFF0BCB0B, 0xFF0BCD0B, 0xFF0BCF0B, 0xFF0BD00B, 0xFF0BD20B, 0xFF0BD30B, 0xFF0BD50B,
    0xFF0BD70B, 0xFF0BD80B, 0xFF0BDA0B, 0xFF0CDB0C, 0xFF0CDD0C, 0xFF0CDF0C, 0xFF0CE00C, 0xFF0CE20C,
    0xFF0CE30C, 0xFF0CE50C, 0xFF0CE70C, 0xFF0CE80C, 0xFF0CEA0C, 0xFF0CEB0C, 0xFF0DED0D, 0xFF0DEF0D,
    0xFF0DF00D, 0xFF0DF20D, 0xFF0DF30D, 0xFF0DF50D, 0xFF0DF70D, 0xFF0DF80D, 0xFF0DFA0D, 0xFF0DFB0D,
    0xFF0DFD0D, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E,
    0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F,
    0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F,
    0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10,
    0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11,
    0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF12FF12,
    0x0, 0xFF1212FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF,
    0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF,
    0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF,
    0xFF1010FF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF,
    0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF,
    0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF,
    0xFF0D0DFD, 0xFF0D0DFB, 0xFF0D0DFA, 0xFF0D0DF8, 0xFF0D0DF7, 0xFF0D0DF5, 0xFF0D0DF3, 0xFF0D0DF2,
    0xFF0D0DF0, 0xFF0D0DEF, 0xFF0D0DED, 0xFF0C0CEB, 0xFF0C0CEA, 0xFF0C0CE8, 0xFF0C0CE7, 0xFF0C0CE5,
    0xFF0C0CE3, 0xFF0C0CE2, 0xFF0C0CE0, 0xFF0C0CDF, 0xFF0C0CDD, 0xFF0C0CDB, 0xFF0B0BDA, 0xFF0B0BD8,
    0xFF0B0BD7, 0xFF0B0BD5, 0xFF0B0BD3, 0xFF0B0BD2, 0xFF0B0BD0, 0xFF0B0BCF, 0xFF0B0BCD, 0xFF0B0BCB,
    0xFF0B0BCA, 0xFF0B0BC8, 0xFF0A0AC7, 0xFF0A0AC5, 0xFF0A0AC3, 0xFF0A0AC2, 0xFF0A0AC0, 0xFF0A0ABF,
    0xFF0A0ABD, 0xFF0A0ABB, 0xFF0A0ABA, 0xFF0A0AB8, 0xFF0A0AB7, 0xFF0909B5, 0xFF0909B3, 0xFF0909B2,
    0xFF0909B0, 0xFF0909AF, 0xFF0909AD, 0xFF0909AB, 0xFF0909AA, 0xFF0909A8, 0xFF0909A7, 0xFF0909A5,
    0xFF0909A3, 0xFF0808A2, 0xFF0808A0, 0xFF08089F, 0xFF08089D, 0xFF08089B, 0xFF08089A, 0xFF080898,
    0xFF080897, 0xFF080895, 0xFF080893, 0xFF080892, 0xFF070790, 0xFF07078F, 0xFF07078D, 0xFF07078B,
    0xFF07078A, 0xFF070788, 0xFF070787, 0xFF070785, 0xFF070783, 0xFF070782, 0xFF070780, 0xFF07077F,
};

void View::DrawMemory()
{
    auto& mem = m_worker.GetMemData();

    ImGui::Begin( "Memory", &m_memInfo.show );

    if( mem.data.empty() )
    {
        ImGui::TextWrapped( "No memory data collected." );
        ImGui::End();
        return;
    }

    ImGui::Text( "Total allocations: %-15s Active allocations: %-15s Memory usage: %-15s Memory span: %s",
        RealToString( mem.data.size(), true ),
        RealToString( mem.active.size(), true ),
        RealToString( mem.usage, true ),
        RealToString( mem.high - mem.low, true ) );

    ImGui::InputText( "", m_memInfo.pattern, 1024 );
    ImGui::SameLine();

    if( ImGui::Button( "Find" ) )
    {
        m_memInfo.ptrFind = strtoull( m_memInfo.pattern, nullptr, 0 );
    }
    ImGui::SameLine();
    if( ImGui::Button( "Clear" ) )
    {
        m_memInfo.ptrFind = 0;
        m_memInfo.pattern[0] = '\0';
    }
    ImGui::SameLine();
    ImGui::Checkbox( "Restrict time", &m_memInfo.restrictTime );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Don't show allocations beyond the middle of timeline" );
        ImGui::Text( "display (it is indicated by purple line)." );
        ImGui::EndTooltip();
    }

    const auto zvMid = m_zvStart + ( m_zvEnd - m_zvStart ) / 2;

    ImGui::Separator();
    if( ImGui::TreeNodeEx( "Allocations", ImGuiTreeNodeFlags_DefaultOpen ) )
    {
        if( m_memInfo.ptrFind != 0 )
        {
            std::vector<const MemEvent*> match;
            match.reserve( mem.active.size() );     // heuristic
            if( m_memInfo.restrictTime )
            {
                for( auto& v : mem.data )
                {
                    if( v.ptr <= m_memInfo.ptrFind && v.ptr + v.size > m_memInfo.ptrFind && v.timeAlloc < zvMid )
                    {
                        match.emplace_back( &v );
                    }
                }
            }
            else
            {
                for( auto& v : mem.data )
                {
                    if( v.ptr <= m_memInfo.ptrFind && v.ptr + v.size > m_memInfo.ptrFind )
                    {
                        match.emplace_back( &v );
                    }
                }
            }

            if( match.empty() )
            {
                ImGui::Text( "Found no allocations at given address" );
            }
            else
            {
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( match.size(), true ) );
                ListMemData<decltype( match.begin() )>( match.begin(), match.end(), [this]( auto& it ) {
                    auto& v = *it;
                    if( v->ptr == m_memInfo.ptrFind )
                    {
                        ImGui::Text( "0x%" PRIx64, m_memInfo.ptrFind );
                    }
                    else
                    {
                        ImGui::Text( "0x%" PRIx64 "+%" PRIu64, v->ptr, m_memInfo.ptrFind - v->ptr );
                    }
                    return v;
                }, "##allocations" );
            }
        }
        ImGui::TreePop();
    }

    ImGui::Separator();
    if( ImGui::TreeNode( "Active allocations" ) )
    {
        uint64_t total = 0;
        std::vector<const MemEvent*> items;
        items.reserve( mem.active.size() );
        if( m_memInfo.restrictTime )
        {
            for( auto& v : mem.data )
            {
                if( v.timeAlloc < zvMid && ( v.timeFree > zvMid || v.timeFree < 0 ) )
                {
                    items.emplace_back( &v );
                    total += v.size;
                }
            }
        }
        else
        {
            auto ptr = mem.data.data();
            for( auto& v : mem.active )
            {
                items.emplace_back( ptr + v.second );
            }
            pdqsort_branchless( items.begin(), items.end(), []( const auto& lhs, const auto& rhs ) { return lhs->timeAlloc < rhs->timeAlloc; } );
            total = mem.usage;
        }

        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( items.size(), true ) );
        ImGui::Text( "Memory usage: %s", RealToString( total, true ) );

        ListMemData<decltype( items.begin() )>( items.begin(), items.end(), []( auto& v ) {
            ImGui::Text( "0x%" PRIx64, (*v)->ptr );
            return *v;
        }, "##activeMem" );
        ImGui::TreePop();
    }

    ImGui::Separator();
    if( ImGui::TreeNode( "Memory map" ) )
    {
        ImGui::Text( "Single pixel: %s KB   Single line: %s KB", RealToString( ( 1 << ChunkBits ) / 1024, true ), RealToString( PageChunkSize / 1024, true ) );

        auto pages = GetMemoryPages();

        const int8_t empty[PageSize] = {};
        const auto sz = pages.second / PageSize;
        auto pgptr = pages.first;
        const auto end = pgptr + sz * PageSize;
        size_t lines = sz;
        while( pgptr != end )
        {
            if( memcmp( empty, pgptr, PageSize ) == 0 )
            {
                pgptr += PageSize;
                while( pgptr != end && memcmp( empty, pgptr, PageSize ) == 0 )
                {
                    lines--;
                    pgptr += PageSize;
                }
            }
            else
            {
                pgptr += PageSize;
            }
        }

        ImGui::BeginChild( "##memMap", ImVec2( PageSize + 2, lines + 2 ), false );
        auto draw = ImGui::GetWindowDrawList();
        const auto wpos = ImGui::GetCursorScreenPos() + ImVec2( 1, 1 );
        draw->AddRect( wpos - ImVec2( 1, 1 ), wpos + ImVec2( PageSize + 1, lines + 1 ), 0xFF666666 );
        draw->AddRectFilled( wpos, wpos + ImVec2( PageSize, lines ), 0xFF444444 );

        size_t line = 0;
        pgptr = pages.first;
        while( pgptr != end )
        {
            if( memcmp( empty, pgptr, PageSize ) == 0 )
            {
                pgptr += PageSize;
                draw->AddLine( wpos + ImVec2( 0, line ), wpos + ImVec2( PageSize, line ), 0x11000000 );
                line++;
                while( pgptr != end && memcmp( empty, pgptr, PageSize ) == 0 ) pgptr += PageSize;
            }
            else
            {
                size_t idx = 0;
                while( idx < PageSize )
                {
                    if( pgptr[idx] == 0 )
                    {
                        do
                        {
                            idx++;
                        }
                        while( idx < PageSize && pgptr[idx] == 0 );
                    }
                    else
                    {
                        auto val = pgptr[idx];
                        const auto i0 = idx;
                        do
                        {
                            idx++;
                        }
                        while( idx < PageSize && pgptr[idx] == val );
                        draw->AddLine( wpos + ImVec2( i0, line ), wpos + ImVec2( idx, line ), MemDecayColor[(uint8_t)val] );
                    }
                }
                line++;
                pgptr += PageSize;
            }
        }

        delete[] pages.first;

        ImGui::EndChild();
        ImGui::TreePop();
    }

    ImGui::End();
}

std::pair<int8_t*, size_t> View::GetMemoryPages() const
{
    const auto& mem = m_worker.GetMemData();
    const auto span = mem.high - mem.low;
    const auto pages = ( span / PageChunkSize ) + 1;

    const auto datasz = pages * PageSize;
    int8_t* data = new int8_t[datasz];
    auto pgptr = data;
    memset( pgptr, 0, pages * PageSize );

    const auto memlow = mem.low;

    if( m_memInfo.restrictTime )
    {
        const auto zvMid = m_zvStart + ( m_zvEnd - m_zvStart ) / 2;
        for( auto& alloc : mem.data )
        {
            if( m_memInfo.restrictTime && alloc.timeAlloc > zvMid ) break;

            const auto a0 = alloc.ptr - memlow;
            const auto a1 = a0 + alloc.size;
            int8_t val = alloc.timeFree < 0 ?
                int8_t( std::max( int64_t( 1 ), 127 - ( ( zvMid - alloc.timeAlloc ) >> 24 ) ) ) :
                ( alloc.timeFree > zvMid ?
                    int8_t( std::max( int64_t( 1 ), 127 - ( ( zvMid - alloc.timeAlloc ) >> 24 ) ) ) :
                    int8_t( -std::max( int64_t( 1 ), 127 - ( ( zvMid - alloc.timeFree ) >> 24 ) ) ) );

            const auto c0 = a0 >> ChunkBits;
            const auto c1 = a1 >> ChunkBits;

            if( c0 == c1 )
            {
                pgptr[c0] = val;
            }
            else
            {
                memset( pgptr + c0, val, c1 - c0 + 1 );
            }
        }
    }
    else
    {
        const auto lastTime = m_worker.GetLastTime();
        for( auto& alloc : mem.data )
        {
            const auto a0 = alloc.ptr - memlow;
            const auto a1 = a0 + alloc.size;
            const int8_t val = alloc.timeFree < 0 ?
                int8_t( std::max( int64_t( 1 ), 127 - ( ( lastTime - std::min( lastTime, alloc.timeAlloc ) ) >> 24 ) ) ) :
                int8_t( -std::max( int64_t( 1 ), 127 - ( ( lastTime - std::min( lastTime, alloc.timeFree ) ) >> 24 ) ) );

            const auto c0 = a0 >> ChunkBits;
            const auto c1 = a1 >> ChunkBits;

            if( c0 == c1 )
            {
                pgptr[c0] = val;
            }
            else
            {
                memset( pgptr + c0, val, c1 - c0 + 1 );
            }
        }
    }

    return std::make_pair( data, datasz );
}

const char* View::GetPlotName( const PlotData* plot ) const
{
    switch( plot->type )
    {
    case PlotType::User:
        return m_worker.GetString( plot->name );
    case PlotType::Memory:
        return "Memory usage";
    default:
        assert( false );
        return nullptr;
    }
}

uint32_t View::GetZoneColor( const ZoneEvent& ev )
{
    const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
    const auto color = srcloc.color;
    return color != 0 ? ( color | 0xFF000000 ) : 0xFFCC5555;
}

uint32_t View::GetZoneColor( const GpuEvent& ev )
{
    const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
    const auto color = srcloc.color;
    return color != 0 ? ( color | 0xFF000000 ) : 0xFF222288;
}

uint32_t View::GetZoneHighlight( const ZoneEvent& ev, bool migration )
{
    if( m_zoneInfoWindow == &ev )
    {
        return 0xFF44DD44;
    }
    else if( m_zoneHighlight == &ev )
    {
        return 0xFF4444FF;
    }
    else if( migration )
    {
        return 0xFFDD22DD;
    }
    else
    {
        const auto color = GetZoneColor( ev );
        return 0xFF000000 |
            ( std::min<int>( 0xFF, ( ( ( color & 0x00FF0000 ) >> 16 ) + 25 ) ) << 16 ) |
            ( std::min<int>( 0xFF, ( ( ( color & 0x0000FF00 ) >> 8  ) + 25 ) ) << 8  ) |
            ( std::min<int>( 0xFF, ( ( ( color & 0x000000FF )       ) + 25 ) )       );
    }
}

uint32_t View::GetZoneHighlight( const GpuEvent& ev )
{
    if( m_gpuInfoWindow == &ev )
    {
        return 0xFF44DD44;
    }
    else if( m_gpuHighlight == &ev )
    {
        return 0xFF4444FF;
    }
    else
    {
        const auto color = GetZoneColor( ev );
        return 0xFF000000 |
            ( std::min<int>( 0xFF, ( ( ( color & 0x00FF0000 ) >> 16 ) + 25 ) ) << 16 ) |
            ( std::min<int>( 0xFF, ( ( ( color & 0x0000FF00 ) >> 8  ) + 25 ) ) << 8  ) |
            ( std::min<int>( 0xFF, ( ( ( color & 0x000000FF )       ) + 25 ) )       );
    }
}

float View::GetZoneThickness( const ZoneEvent& ev )
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

float View::GetZoneThickness( const GpuEvent& ev )
{
    if( m_gpuInfoWindow == &ev || m_gpuHighlight == &ev )
    {
        return 3.f;
    }
    else
    {
        return 1.f;
    }
}

void View::ZoomToZone( const ZoneEvent& ev )
{
    const auto end = m_worker.GetZoneEnd( ev );
    if( end - ev.start <= 0 ) return;
    ZoomToRange( ev.start, end );
}

void View::ZoomToZone( const GpuEvent& ev )
{
    const auto end = m_worker.GetZoneEnd( ev );
    if( end - ev.gpuStart <= 0 ) return;
    auto ctx = GetZoneCtx( ev );
    if( !ctx )
    {
        ZoomToRange( ev.gpuStart, end );
    }
    else
    {
        const auto begin = ctx->timeline.front()->gpuStart;
        const auto drift = GpuDrift( ctx );
        ZoomToRange( AdjustGpuTime( ev.gpuStart, begin, drift ), AdjustGpuTime( end, begin, drift ) );
    }
}

void View::ZoomToRange( int64_t start, int64_t end )
{
    m_pause = true;
    m_zoomAnim.active = true;
    m_zoomAnim.start0 = m_zvStart;
    m_zoomAnim.start1 = start;
    m_zoomAnim.end0 = m_zvEnd;
    m_zoomAnim.end1 = end;
    m_zoomAnim.progress = 0;

    const auto d0 = double( m_zoomAnim.end0 - m_zoomAnim.start0 );
    const auto d1 = double( m_zoomAnim.end1 - m_zoomAnim.start1 );
    const auto diff = d0>d1 ? d0/d1 : d1/d0;
    m_zoomAnim.lenMod = 10.0 / log10( diff );
}

void View::ZoomToPrevFrame()
{
    if( m_zvStart >= m_worker.GetFrameBegin( 0 ) )
    {
        auto frame = m_worker.GetFrameRange( m_zvStart, m_zvStart ).first;
        if( frame > 0 )
        {
            frame--;
            const auto fbegin = m_worker.GetFrameBegin( frame );
            const auto fend = m_worker.GetFrameEnd( frame );
            ZoomToRange( fbegin, fend );
        }
    }
}

void View::ZoomToNextFrame()
{
    int frame;
    if( m_zvStart < m_worker.GetFrameBegin( 0 ) )
    {
        frame = -1;
    }
    else
    {
        frame = m_worker.GetFrameRange( m_zvStart, m_zvStart ).first;
        if( frame == -1 ) return;
    }
    frame++;
    if( frame >= m_worker.GetFrameCount() ) return;

    const auto fbegin = m_worker.GetFrameBegin( frame );
    const auto fend = m_worker.GetFrameEnd( frame );
    ZoomToRange( fbegin, fend );
}

void View::CenterAtTime( int64_t t )
{
    const auto hr = std::max<uint64_t>( 1, ( m_zvEnd - m_zvStart ) / 2 );
    ZoomToRange( t - hr, t + hr );
}

void View::ShowZoneInfo( const ZoneEvent& ev )
{
    if( m_zoneInfoWindow )
    {
        m_zoneInfoStack.push_back( m_zoneInfoWindow );
    }
    m_zoneInfoWindow = &ev;

    if( m_gpuInfoWindow )
    {
        m_gpuInfoWindow = nullptr;
        m_gpuInfoStack.clear();
    }
}

void View::ShowZoneInfo( const GpuEvent& ev, uint64_t thread )
{
    if( m_gpuInfoWindow )
    {
        m_gpuInfoStack.push_back( m_gpuInfoWindow );
    }
    m_gpuInfoWindow = &ev;
    m_gpuInfoWindowThread = thread;

    if( m_zoneInfoWindow )
    {
        m_zoneInfoWindow = nullptr;
        m_zoneInfoStack.clear();
    }
}

void View::ZoneTooltip( const ZoneEvent& ev )
{
    const auto tid = GetZoneThread( ev );
    auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
    const auto end = m_worker.GetZoneEnd( ev );

    ImGui::BeginTooltip();
    if( ev.name.active )
    {
        ImGui::Text( "%s", m_worker.GetString( ev.name ) );
    }
    if( srcloc.name.active )
    {
        ImGui::Text( "%s", m_worker.GetString( srcloc.name ) );
    }
    ImGui::Text( "%s", m_worker.GetString( srcloc.function ) );
    ImGui::Separator();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(0x%" PRIX64 ")", tid );
    ImGui::Separator();
    TextFocused( "Execution time:", TimeToString( end - ev.start ) );
    if( ev.cpu_start >= 0 )
    {
        ImGui::TextDisabled( "CPU:" );
        ImGui::SameLine();
        if( ev.end < 0 || ev.cpu_start == ev.cpu_end )
        {
            ImGui::Text( "%i", ev.cpu_start );
        }
        else
        {
            ImGui::Text( "%i -> %i", ev.cpu_start, ev.cpu_end );
        }
    }
    if( ev.text.active )
    {
        ImGui::NewLine();
        ImGui::TextColored( ImVec4( 0xCC / 255.f, 0xCC / 255.f, 0x22 / 255.f, 1.f ), "%s", m_worker.GetString( ev.text ) );
    }
    ImGui::EndTooltip();
}

void View::ZoneTooltip( const GpuEvent& ev )
{
    const auto tid = GetZoneThread( ev );
    const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
    const auto end = m_worker.GetZoneEnd( ev );

    ImGui::BeginTooltip();
    ImGui::Text( "%s", m_worker.GetString( srcloc.name ) );
    ImGui::Text( "%s", m_worker.GetString( srcloc.function ) );
    ImGui::Separator();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(0x%" PRIX64 ")", tid );
    ImGui::Separator();
    TextFocused( "GPU execution time:", TimeToString( end - ev.gpuStart ) );
    TextFocused( "CPU command setup time:", TimeToString( ev.cpuEnd - ev.cpuStart ) );
    auto ctx = GetZoneCtx( ev );
    if( !ctx )
    {
        TextFocused( "Delay to execution:", TimeToString( ev.gpuStart - ev.cpuStart ) );
    }
    else
    {
        const auto begin = ctx->timeline.front()->gpuStart;
        const auto drift = GpuDrift( ctx );
        TextFocused( "Delay to execution:", TimeToString( AdjustGpuTime( ev.gpuStart, begin, drift ) - ev.cpuStart ) );
    }

    ImGui::EndTooltip();
}

void View::CallstackTooltip( uint32_t idx )
{
    auto& cs = m_worker.GetCallstack( idx );

    ImGui::BeginTooltip();
    int fidx = 0;
    for( auto& entry : cs )
    {
        ImGui::TextDisabled( "%i.", fidx++ );
        ImGui::SameLine();
        auto frame = m_worker.GetCallstackFrame( entry );
        if( !frame )
        {
            ImGui::Text( "0x%" PRIX64, entry );
        }
        else
        {
            ImGui::Text( "%s", m_worker.GetString( frame->name ) );
        }
    }
    ImGui::EndTooltip();
}

const ZoneEvent* View::GetZoneParent( const ZoneEvent& zone ) const
{
    for( const auto& thread : m_worker.GetThreadData() )
    {
        const ZoneEvent* parent = nullptr;
        const Vector<ZoneEvent*>* timeline = &thread->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.start, [] ( const auto& l, const auto& r ) { return l < r->start; } );
            if( it != timeline->begin() ) --it;
            if( zone.end >= 0 && (*it)->start > zone.end ) break;
            if( *it == &zone ) return parent;
            if( (*it)->child.empty() ) break;
            parent = *it;
            timeline = &parent->child;
        }
    }
    return nullptr;
}

const GpuEvent* View::GetZoneParent( const GpuEvent& zone ) const
{
    for( const auto& ctx : m_worker.GetGpuData() )
    {
        const GpuEvent* parent = nullptr;
        const Vector<GpuEvent*>* timeline = &ctx->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.gpuStart, [] ( const auto& l, const auto& r ) { return l < r->gpuStart; } );
            if( it != timeline->begin() ) --it;
            if( zone.gpuEnd >= 0 && (*it)->gpuStart > zone.gpuEnd ) break;
            if( *it == &zone ) return parent;
            if( (*it)->child.empty() ) break;
            parent = *it;
            timeline = &parent->child;
        }
    }
    return nullptr;
}

uint64_t View::GetZoneThread( const ZoneEvent& zone ) const
{
    for( const auto& thread : m_worker.GetThreadData() )
    {
        const Vector<ZoneEvent*>* timeline = &thread->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.start, [] ( const auto& l, const auto& r ) { return l < r->start; } );
            if( it != timeline->begin() ) --it;
            if( zone.end >= 0 && (*it)->start > zone.end ) break;
            if( *it == &zone ) return thread->id;
            if( (*it)->child.empty() ) break;
            timeline = &(*it)->child;
        }
    }
    return 0;
}

uint64_t View::GetZoneThread( const GpuEvent& zone ) const
{
    if( zone.thread == 0 )
    {
        for( const auto& ctx : m_worker.GetGpuData() )
        {
            const Vector<GpuEvent*>* timeline = &ctx->timeline;
            if( timeline->empty() ) continue;
            for(;;)
            {
                auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.gpuStart, [] ( const auto& l, const auto& r ) { return l < r->gpuStart; } );
                if( it != timeline->begin() ) --it;
                if( zone.gpuEnd >= 0 && (*it)->gpuStart > zone.gpuEnd ) break;
                if( *it == &zone ) return ctx->thread;
                if( (*it)->child.empty() ) break;
                timeline = &(*it)->child;
            }
        }
        return 0;
    }
    else
    {
        return m_worker.DecompressThread( zone.thread );
    }
}

const GpuCtxData* View::GetZoneCtx( const GpuEvent& zone ) const
{
    for( const auto& ctx : m_worker.GetGpuData() )
    {
        const Vector<GpuEvent*>* timeline = &ctx->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.gpuStart, [] ( const auto& l, const auto& r ) { return l < r->gpuStart; } );
            if( it != timeline->begin() ) --it;
            if( zone.gpuEnd >= 0 && (*it)->gpuStart > zone.gpuEnd ) break;
            if( *it == &zone ) return ctx;
            if( (*it)->child.empty() ) break;
            timeline = &(*it)->child;
        }
    }
    return nullptr;
}

const ZoneEvent* View::FindZoneAtTime( uint64_t thread, int64_t time ) const
{
    // TODO add thread rev-map
    ThreadData* td = nullptr;
    for( const auto& t : m_worker.GetThreadData() )
    {
        if( t->id == thread )
        {
            td = t;
            break;
        }
    }
    if( !td ) return nullptr;

    const Vector<ZoneEvent*>* timeline = &td->timeline;
    if( timeline->empty() ) return nullptr;
    ZoneEvent* ret = nullptr;
    for(;;)
    {
        auto it = std::upper_bound( timeline->begin(), timeline->end(), time, [] ( const auto& l, const auto& r ) { return l < r->start; } );
        if( it != timeline->begin() ) --it;
        if( (*it)->start > time || ( (*it)->end >= 0 && (*it)->end < time ) ) return ret;
        ret = *it;
        if( (*it)->child.empty() ) return ret;
        timeline = &(*it)->child;
    }
}

#ifndef TRACY_NO_STATISTICS
void View::FindZones()
{
    m_findZone.match = m_worker.GetMatchingSourceLocation( m_findZone.pattern );
    if( m_findZone.match.empty() ) return;

    auto it = m_findZone.match.begin();
    while( it != m_findZone.match.end() )
    {
        if( m_worker.GetZonesForSourceLocation( *it ).zones.empty() )
        {
            it = m_findZone.match.erase( it );
        }
        else
        {
            ++it;
        }
    }
}

void View::FindZonesCompare()
{
    m_compare.match[0] = m_worker.GetMatchingSourceLocation( m_compare.pattern );
    if( !m_compare.match[0].empty() )
    {
        auto it = m_compare.match[0].begin();
        while( it != m_compare.match[0].end() )
        {
            if( m_worker.GetZonesForSourceLocation( *it ).zones.empty() )
            {
                it = m_compare.match[0].erase( it );
            }
            else
            {
                ++it;
            }
        }
    }

    m_compare.match[1] = m_compare.second->GetMatchingSourceLocation( m_compare.pattern );
    if( !m_compare.match[1].empty() )
    {
        auto it = m_compare.match[1].begin();
        while( it != m_compare.match[1].end() )
        {
            if( m_compare.second->GetZonesForSourceLocation( *it ).zones.empty() )
            {
                it = m_compare.match[1].erase( it );
            }
            else
            {
                ++it;
            }
        }
    }
}
#endif

}
