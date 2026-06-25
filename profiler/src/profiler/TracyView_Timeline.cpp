#include <algorithm>

#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracySourceView.hpp"
#include "TracyTimelineItemCpuData.hpp"
#include "TracyTimelineItemGpu.hpp"
#include "TracyTimelineItemPlot.hpp"
#include "TracyTimelineItemThread.hpp"
#include "TracyView.hpp"
#include "../Fonts.hpp"

namespace tracy
{

extern double s_time;

void View::HandleTimelineMouse( int64_t timespan, const ImVec2& wpos, float w )
{
    assert( timespan > 0 );
    auto& io = ImGui::GetIO();

    const auto nspx = double( timespan ) / w;

    if( IsMouseClicked( 0 ) )
    {
        m_highlight.active = true;
        m_highlight.start = m_highlight.end = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( IsMouseDragging( 0 ) )
    {
        m_highlight.end = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( m_highlight.active && !IsMouseDown( 0 ) )
    {
        if( ImGui::GetIO().KeyCtrl && m_highlight.start != m_highlight.end )
        {
            m_setRangePopup = RangeSlim { m_highlight.start, m_highlight.end, true };
        }
        m_highlight.active = false;
    }

    if( IsMouseClicked( 2 ) )
    {
        m_highlightZoom.active = true;
        m_highlightZoom.start = m_highlightZoom.end = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( IsMouseDragging( 2 ) )
    {
        m_highlightZoom.end = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( m_highlightZoom.active && !IsMouseDown( 2 )  )
    {
        if( m_highlightZoom.start != m_highlightZoom.end )
        {
            const auto s = std::min( m_highlightZoom.start, m_highlightZoom.end );
            const auto e = std::max( m_highlightZoom.start, m_highlightZoom.end );

            // ZoomToRange disables m_highlightZoom.active
            if( io.KeyCtrl )
            {
                const auto tsOld = m_vd.zvEnd - m_vd.zvStart;
                const auto tsNew = e - s;
                const auto mul = double( tsOld ) / tsNew;
                const auto left = s - m_vd.zvStart;
                const auto right = m_vd.zvEnd - e;

                auto start = m_vd.zvStart - left * mul;
                auto end = m_vd.zvEnd + right * mul;
                if( end - start > 1000ll * 1000 * 1000 * 60 * 60 * 24 * 10 )
                {
                    start = -1000ll * 1000 * 1000 * 60 * 60 * 24 * 5;
                    end = 1000ll * 1000 * 1000 * 60 * 60 * 24 * 5;
                }

                ZoomToRange( start, end );
            }
            else
            {
                ZoomToRange( s, e );
            }
        }
        else
        {
            m_highlightZoom.active = false;
        }
    }

    const bool wheel_scroll = abs( io.MouseWheelH ) > abs( io.MouseWheel );
    if( IsMouseDragging( 1 ) || wheel_scroll )
    {
        m_viewMode = ViewMode::Paused;
        m_viewModeHeuristicTry = false;
        m_zoomAnim.active = false;
        if( !m_playback.pause && m_playback.sync ) m_playback.pause = true;
        const auto delta = GetMouseDragDelta( 1 );
        m_yDelta = delta.y;
        const auto hwheel_delta = io.MouseWheelH * 50.f * m_horizontalScrollMultiplier;
        const auto dpx = int64_t( (delta.x * nspx) + (hwheel_delta * nspx));
        if( dpx != 0 )
        {
            m_vd.zvStart -= dpx;
            m_vd.zvEnd -= dpx;
            io.MouseClickedPos[1].x = io.MousePos.x;

            if( m_vd.zvStart < -1000ll * 1000 * 1000 * 60 * 60 * 24 * 5 )
            {
                const auto range = m_vd.zvEnd - m_vd.zvStart;
                m_vd.zvStart = -1000ll * 1000 * 1000 * 60 * 60 * 24 * 5;
                m_vd.zvEnd = m_vd.zvStart + range;
            }
            else if( m_vd.zvEnd > 1000ll * 1000 * 1000 * 60 * 60 * 24 * 5 )
            {
                const auto range = m_vd.zvEnd - m_vd.zvStart;
                m_vd.zvEnd = 1000ll * 1000 * 1000 * 60 * 60 * 24 * 5;
                m_vd.zvStart = m_vd.zvEnd - range;
            }
        }
    }

    const bool wheel_zoom = abs( io.MouseWheel ) > abs( io.MouseWheelH );
    if( wheel_zoom )
    {
        const auto wheel = io.MouseWheel;
        if( m_viewMode == ViewMode::LastFrames ) m_viewMode = ViewMode::LastRange;
        const double mouse = io.MousePos.x - wpos.x;
        const auto p = mouse / w;

        int64_t t0, t1;
        if( m_zoomAnim.active )
        {
            t0 = m_zoomAnim.start1;
            t1 = m_zoomAnim.end1;
        }
        else
        {
            t0 = m_vd.zvStart;
            t1 = m_vd.zvEnd;
        }
        const auto zoomSpan = t1 - t0;
        const auto p1 = zoomSpan * p;
        const auto p2 = zoomSpan - p1;

        double mod = 0.25;
        if( io.KeyCtrl ) mod = 0.05;
        else if( io.KeyShift ) mod = 0.5;

        mod *= m_verticalScrollMultiplier;
#ifndef __EMSCRIPTEN__
        mod *= fabs( wheel );
#endif

        if( wheel > 0 )
        {
            t0 += int64_t( p1 * mod );
            t1 -= int64_t( p2 * mod );
        }
        else if( zoomSpan < 1000ll * 1000 * 1000 * 60 * 60 )
        {
            t0 -= std::max( int64_t( 1 ), int64_t( p1 * mod ) );
            t1 += std::max( int64_t( 1 ), int64_t( p2 * mod ) );
        }
        t1 = std::max(t0, t1);
        ZoomToRange( t0, t1, !m_worker.IsConnected() || m_viewMode == ViewMode::Paused );
    }
}

void View::HandleTimelineKeyboard( int64_t timespan, const ImVec2& wpos, float w )
{
    assert( timespan > 0 );
    auto& io = ImGui::GetIO();

    int64_t nextTimelineRangeStart, nextTimelineRangeEnd;
    bool anyDeltaApplied = false;
    if( m_zoomAnim.active )
    {
        nextTimelineRangeStart = m_zoomAnim.start1;
        nextTimelineRangeEnd = m_zoomAnim.end1;
    }
    else
    {
        nextTimelineRangeStart = m_vd.zvStart;
        nextTimelineRangeEnd = m_vd.zvEnd;
    }

    const auto bias = (io.MousePos.x - wpos.x) / w;
    const auto span = nextTimelineRangeEnd - nextTimelineRangeStart;
    // Move at a rate of 1/10th the length of the timeline per second, with a minimum of 500ns
    const auto moveInTimelineNanos = std::max<int64_t>( span / 10, 500 );
    const auto movement = moveInTimelineNanos * std::max( std::min( io.DeltaTime, 0.25f ), 0.016f );

    for( int direction = 0; direction < 4; direction++ )
    {
        auto& inertia = m_kbNavCtrl.m_scrollInertia[direction];

        if( ImGui::IsKeyDown( KeyboardNavigation::DirectionToKeyMap[direction] ) )
        {
            const auto timeStartDelta = movement * KeyboardNavigation::StartRangeMod[direction];
            const auto timeEndDelta = movement * KeyboardNavigation::EndRangeMod[direction];

            // This part is completely arbitrary, designed to work in the range ~ 0 -> 15
            const auto x = inertia / 10.0f;
            const auto mult = 1 + std::max( 0.0, 0.7 * std::pow( x, 1.6 ) - 0.8 * std::pow( x, 1.4 ) );

            // If we are zooming in/out
            if( direction > KeyboardNavigation::Right )
            {
                // Bias if equal is 0.5. Multiply by 2 to offset back to the expected movement range.
                nextTimelineRangeStart += timeStartDelta * mult * 2 * bias;
                nextTimelineRangeEnd += timeEndDelta * mult * 2 * (1 - bias);
            }
            else
            {
                nextTimelineRangeStart += timeStartDelta * mult;
                nextTimelineRangeEnd += timeEndDelta * mult;
            }

            inertia = std::min( 150.0f, inertia + 1 );
            anyDeltaApplied = true;
        }
        else
        {
            inertia = std::max( 0.0f, inertia - 1 );
        }
    }

    if( anyDeltaApplied )
    {
        if( m_viewMode == ViewMode::LastFrames ) m_viewMode = ViewMode::LastRange;
        if( nextTimelineRangeStart > nextTimelineRangeEnd ) return;

        // We want to cap the zoom at the range of values that the timeline has data for
        const auto firstTime = m_worker.GetFirstTime();
        const auto lastTime = m_worker.GetLastTime();

        nextTimelineRangeStart = std::max<int64_t>( std::min( nextTimelineRangeStart, lastTime - 50 ), firstTime );
        nextTimelineRangeEnd = std::max<int64_t>( std::min( nextTimelineRangeEnd, lastTime ), firstTime+1 );

        if( nextTimelineRangeEnd - nextTimelineRangeStart <= 50 ) return;
        const auto shouldPause = m_viewMode == ViewMode::Paused || !m_worker.IsConnected();
        ZoomToRange( nextTimelineRangeStart, nextTimelineRangeEnd, shouldPause );
    }
}


void View::DrawTimeline()
{
    m_msgHighlight.Decay( nullptr );
    m_zoneSrcLocHighlight.Decay( 0 );
    m_lockHoverHighlight.Decay( InvalidId );

    if( !m_vd.drawCpuData )
    {
        m_selectedThread = 0;
    }
    m_drawThreadMigrations.Decay( 0 );
    m_drawThreadHighlight.Decay( 0 );
    m_cpuDataThread.Decay( 0 );
    m_zoneHover = nullptr;
    m_zoneHover2.Decay( nullptr );
    for( auto& r : m_ranges ) r.range->StartFrame();
    m_yDelta = 0;
    m_nextLockHighlight = { -1 };

    if( m_vd.zvStart == m_vd.zvEnd ) return;
    assert( m_vd.zvStart < m_vd.zvEnd );

    if( ImGui::GetCurrentWindowRead()->SkipItems ) return;

    m_gpuThread = 0;
    m_gpuStart = 0;
    m_gpuEnd = 0;

    const auto linepos = ImGui::GetCursorScreenPos();
    const auto lineh = ImGui::GetContentRegionAvail().y;

    auto draw = ImGui::GetWindowDrawList();
    const auto w = ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ScrollbarSize;
    const auto timespan = m_vd.zvEnd - m_vd.zvStart;
    auto pxns = w / double( timespan );

    const auto winpos = ImGui::GetWindowPos();
    const auto winsize = ImGui::GetWindowSize();
    const bool drawMouseLine = ImGui::IsWindowHovered( ImGuiHoveredFlags_ChildWindows | ImGuiHoveredFlags_AllowWhenBlockedByActiveItem ) && ImGui::IsMouseHoveringRect( winpos, winpos + winsize, false );
    if( drawMouseLine )
    {
        for( auto& r : m_ranges ) HandleRange( *r.range, timespan, ImGui::GetCursorScreenPos(), w );
        for( auto& v : m_annotations )
        {
            if( !v->visible ) continue;
            v->range.StartFrame();
            HandleRange( v->range, timespan, ImGui::GetCursorScreenPos(), w );
        }
        if( IsMouseClicked( 0 ) )
        {
            const auto ty = ImGui::GetTextLineHeight();
            for( auto& ann : m_annotations )
            {
                if( !ann->visible || ann->range.min >= m_vd.zvEnd || ann->range.max <= m_vd.zvStart ) continue;
                const auto aMin = ( ann->range.min - m_vd.zvStart ) * pxns;
                const auto aMax = ( ann->range.max - m_vd.zvStart ) * pxns;
                if( ImGui::IsMouseHoveringRect( linepos + ImVec2( aMin, lineh - ty * 1.5f ), linepos + ImVec2( aMax, lineh ) ) )
                {
                    m_selectedAnnotation = ann.get();
                    ConsumeMouseEvents( 0 );
                    break;
                }
            }
        }
        HandleTimelineMouse( timespan, ImGui::GetCursorScreenPos(), w );
    }
    if( ImGui::IsWindowFocused( ImGuiHoveredFlags_ChildWindows | ImGuiHoveredFlags_AllowWhenBlockedByActiveItem ) )
    {
        HandleTimelineKeyboard( timespan, ImGui::GetCursorScreenPos(), w );
    }

    {
        const auto tbegin = m_worker.GetFirstTime();
        const auto tend = m_worker.GetLastTime();
        if( tbegin > m_vd.zvStart )
        {
            draw->AddRectFilled( linepos, linepos + ImVec2( ( tbegin - m_vd.zvStart ) * pxns, lineh ), 0x44000000 );
        }
        if( tend < m_vd.zvEnd )
        {
            draw->AddRectFilled( linepos + ImVec2( ( tend - m_vd.zvStart ) * pxns, 0 ), linepos + ImVec2( w, lineh ), 0x44000000 );
        }
    }

    m_tc.Begin();
    DrawTimelineFramesHeader();
    if( m_worker.AreFramesUsed() )
    {
        auto& frames = m_worker.GetFrames();
        for( auto fd : frames )
        {
            if( Vis( fd ) )
            {
                DrawTimelineFrames( *fd );
            }
        }
    }
    DrawTimelineSections();

    const auto yMin = ImGui::GetCursorScreenPos().y;
    const auto yMax = linepos.y + lineh;

    draw->AddLineH( winpos.x, winpos.x + ImGui::GetContentRegionAvail().x + 1, yMin - 1, 0x0FFFFFFF );

    ImGui::SetNextWindowContentSize( ImVec2( 0, m_tc.GetHeight() ) );
    ImGui::BeginChild( "##zoneWin", ImVec2( ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y ), false, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_NoScrollWithMouse );

    const auto verticallyCenterTimeline = true;

    if( m_yDelta != 0 )
    {
        auto& io = ImGui::GetIO();
        if( !verticallyCenterTimeline )
        {
            auto y = ImGui::GetScrollY();
            ImGui::SetScrollY( y - m_yDelta );
        }
        io.MouseClickedPos[1].y = io.MousePos.y;
    }

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto h = std::max<float>( m_tc.GetHeight(), ImGui::GetContentRegionAvail().y - 4 );    // magic border value

    ImGui::ItemSize( ImVec2( w, h ) );
    bool hover = ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect( wpos, wpos + ImVec2( w, h ) );
    draw = ImGui::GetWindowDrawList();

    const auto scale = GetScale();
    const auto ty = ImGui::GetTextLineHeight();

    if( m_vd.drawGpuZones )
    {
        for( auto& v : m_worker.GetGpuData() )
        {
            m_tc.AddItem<TimelineItemGpu>( v );
        }
    }
    if( m_vd.drawCpuData && m_worker.HasContextSwitches() )
    {
        static char uptr;
        m_tc.AddItem<TimelineItemCpuData>( &uptr );
    }
    if( m_vd.drawZones )
    {
        UpdateThreadOrder();
        for( const auto& v : m_threadOrder )
        {
            m_tc.AddItem<TimelineItemThread>( v );
        }
    }
    if( m_vd.drawPlots )
    {
        for( const auto& v : m_worker.GetPlots() )
        {
            m_tc.AddItem<TimelineItemPlot>( v );
        }
    }

    const auto vcenter = verticallyCenterTimeline && drawMouseLine && m_viewMode == ViewMode::Paused;
    m_tc.End( pxns, wpos, hover, vcenter, yMin, yMax );
    ImGui::EndChild();

    m_lockHighlight = m_nextLockHighlight;

    const auto iconSize = ImGui::CalcTextSize( ICON_FA_NOTE_STICKY );
    for( auto& ann : m_annotations )
    {
        if( ann->visible && ann->range.min < m_vd.zvEnd && ann->range.max > m_vd.zvStart )
        {
            uint32_t c0 = ( ann->color & 0xFFFFFF ) | ( m_selectedAnnotation == ann.get() ? 0x22000000 : 0x11000000 );
            uint32_t c1 = ( ann->color & 0xFFFFFF ) | ( m_selectedAnnotation == ann.get() ? 0x88000000 : 0x66000000 );
            uint32_t c2 = ( ann->color & 0xFFFFFF ) | ( m_selectedAnnotation == ann.get() ? 0xDD000000 : 0xBB000000 );

            const auto aMin = ( ann->range.min - m_vd.zvStart ) * pxns;
            const auto aMax = ( ann->range.max - m_vd.zvStart ) * pxns;

            draw->AddRectFilled( linepos + ImVec2( aMin, 0 ), linepos + ImVec2( aMax, lineh ), c0 );
            draw->AddRectFilled( linepos + ImVec2( aMin + 1, lineh - ty * 1.5f ), linepos + ImVec2( aMax - 1, lineh ), 0x88000000 );
            DrawLine( draw, linepos + ImVec2( aMin + 0.5f, 0.5f ), linepos + ImVec2( aMin + 0.5f, lineh + 0.5f ), ann->range.hiMin ? c2 : c1, ann->range.hiMin ? 2 : 1 );
            DrawLine( draw, linepos + ImVec2( aMax - 0.5f, 0.5f ), linepos + ImVec2( aMax - 0.5f, lineh + 0.5f ), ann->range.hiMax ? c2 : c1, ann->range.hiMax ? 2 : 1 );

            if( drawMouseLine && ImGui::IsMouseHoveringRect( linepos + ImVec2( aMin, 0 ), linepos + ImVec2( aMax, lineh ) ) )
            {
                ImGui::BeginTooltip();
                TextDisabledUnformatted( ICON_FA_NOTE_STICKY );
                ImGui::SameLine();
                if( ann->text.empty() )
                {
                    TextDisabledUnformatted( "Empty annotation" );
                }
                else
                {
                    ImGui::TextUnformatted( ann->text.c_str() );
                }
                ImGui::Separator();
                TextFocused( "Annotation begin:", TimeToStringExact( ann->range.min ) );
                TextFocused( "Annotation end:", TimeToStringExact( ann->range.max ) );
                TextFocused( "Annotation length:", TimeToString( ann->range.max - ann->range.min ) );
                ImGui::EndTooltip();
            }

            const auto aw = ( ann->range.max - ann->range.min ) * pxns;
            if( aw > ty + iconSize.x )
            {
                draw->AddText( linepos + ImVec2( aMin + ty * 0.5f, lineh - ty * 1.25f ), ann->color | 0xFF000000, ICON_FA_NOTE_STICKY );
                if( !ann->text.empty() )
                {
                    const auto tw = ImGui::CalcTextSize( ann->text.c_str() ).x;
                    if( aw > ty + iconSize.x + tw )
                    {
                        draw->AddText( linepos + ImVec2( aMin + ty + iconSize.x, lineh - ty * 1.25f ), 0xFFFFFFFF, ann->text.c_str() );
                    }
                    else
                    {
                        draw->PushClipRect( linepos + ImVec2( aMin + 1, lineh - ty * 1.5f ), linepos + ImVec2( aMax - 1, lineh ) );
                        draw->AddText( linepos + ImVec2( aMin + ty + iconSize.x, lineh - ty * 1.25f ), 0xFFFFFFFF, ann->text.c_str() );
                        draw->PopClipRect();
                    }
                }
            }
        }
    }

    if( m_gpuStart != 0 && m_gpuEnd != 0 )
    {
        const auto px0 = ( m_gpuStart - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_gpuEnd - m_vd.zvStart ) * pxns );
        draw->AddRectFilled( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x228888DD );
        draw->AddRect( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x448888DD );
    }
    if( m_gpuInfoWindow )
    {
        const auto px0 = ( m_gpuInfoWindow->CpuStart() - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_gpuInfoWindow->CpuEnd() - m_vd.zvStart ) * pxns );
        draw->AddRectFilled( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x2288DD88 );
        draw->AddRect( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x4488DD88 );
    }

    int idx = 0;
    for( auto& r : m_ranges )
    {
        if( r.range->active && ShouldDrawRange( RangeId( idx ) ) )
        {
            const auto px0 = ( r.range->min - m_vd.zvStart ) * pxns;
            const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( r.range->max - m_vd.zvStart ) * pxns );
            const auto alpha = ( r.range->hiMin || r.range->hiMax ) ? 0x12000000 : 0x06000000;
            DrawStripedRect( draw, wpos, px0, linepos.y, px1, linepos.y + lineh, 10 * scale, r.color | alpha, true, idx % 2 == 0 );
            DrawLine( draw, ImVec2( dpos.x + px0, linepos.y + 0.5f ), ImVec2( dpos.x + px0, linepos.y + lineh + 0.5f ), r.color | ( r.range->hiMin ? 0x99000000 : 0x55000000 ), r.range->hiMin ? 2 : 1 );
            DrawLine( draw, ImVec2( dpos.x + px1, linepos.y + 0.5f ), ImVec2( dpos.x + px1, linepos.y + lineh + 0.5f ), r.color | ( r.range->hiMax ? 0x99000000 : 0x55000000 ), r.range->hiMax ? 2 : 1 );
        }
        idx++;
    }

    if( m_setRangePopup.active || m_setRangePopupOpen )
    {
        const auto s = std::min( m_setRangePopup.min, m_setRangePopup.max );
        const auto e = std::max( m_setRangePopup.min, m_setRangePopup.max );
        DrawStripedRect( draw, wpos, ( s - m_vd.zvStart ) * pxns, linepos.y, ( e - m_vd.zvStart ) * pxns, linepos.y + lineh, 5 * scale, 0x11DD8888, true, false );
        draw->AddRect( ImVec2( wpos.x + ( s - m_vd.zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_vd.zvStart ) * pxns, linepos.y + lineh ), 0x77DD8888 );
    }

    if( m_highlight.active && m_highlight.start != m_highlight.end )
    {
        const auto s = std::min( m_highlight.start, m_highlight.end );
        const auto e = std::max( m_highlight.start, m_highlight.end );
        draw->AddRectFilled( ImVec2( wpos.x + ( s - m_vd.zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_vd.zvStart ) * pxns, linepos.y + lineh ), 0x22DD8888 );
        draw->AddRect( ImVec2( wpos.x + ( s - m_vd.zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_vd.zvStart ) * pxns, linepos.y + lineh ), 0x44DD8888 );

        ImGui::BeginTooltip();
        ImGui::TextUnformatted( TimeToString( e - s ) );
        ImGui::EndTooltip();
    }
    else if( drawMouseLine )
    {
        auto& io = ImGui::GetIO();
        DrawLine( draw, ImVec2( io.MousePos.x + 0.5f, linepos.y + 0.5f ), ImVec2( io.MousePos.x + 0.5f, linepos.y + lineh + 0.5f ), 0x33FFFFFF );
    }

    if( m_highlightZoom.active && m_highlightZoom.start != m_highlightZoom.end )
    {
        const auto s = std::min( m_highlightZoom.start, m_highlightZoom.end );
        const auto e = std::max( m_highlightZoom.start, m_highlightZoom.end );
        draw->AddRectFilled( ImVec2( wpos.x + ( s - m_vd.zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_vd.zvStart ) * pxns, linepos.y + lineh ), 0x1688DD88 );
        draw->AddRect( ImVec2( wpos.x + ( s - m_vd.zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_vd.zvStart ) * pxns, linepos.y + lineh ), 0x2C88DD88 );
    }
}

}
