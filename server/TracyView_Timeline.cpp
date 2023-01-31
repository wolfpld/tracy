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

namespace tracy
{

extern double s_time;

void View::HandleTimelineMouse( int64_t timespan, const ImVec2& wpos, float w, double& pxns )
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
    else if( m_highlight.active )
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
    else if( m_highlightZoom.active )
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

    const auto hwheel_delta = io.MouseWheelH * 100.f;
    if( IsMouseDragging( 1 ) || hwheel_delta != 0 )
    {
        m_viewMode = ViewMode::Paused;
        m_viewModeHeuristicTry = false;
        m_zoomAnim.active = false;
        if( !m_playback.pause && m_playback.sync ) m_playback.pause = true;
        const auto delta = GetMouseDragDelta( 1 );
        m_yDelta = delta.y;
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

    const auto wheel = io.MouseWheel;
    if( wheel != 0 )
    {
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
        const auto lastKnownTime = m_worker.GetLastTime();

        // Bring into the range 0 -> lastKnownTime - 50 (must

        nextTimelineRangeStart = std::max<int64_t>( std::min( nextTimelineRangeStart, lastKnownTime - 50 ), 0 );
        nextTimelineRangeEnd = std::max<int64_t>( std::min( nextTimelineRangeEnd, lastKnownTime ), 1 );

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
    m_drawThreadMigrations.Decay( 0 );
    m_drawThreadHighlight.Decay( 0 );
    m_cpuDataThread.Decay( 0 );
    m_zoneHover = nullptr;
    m_zoneHover2.Decay( nullptr );
    m_findZone.range.StartFrame();
    m_statRange.StartFrame();
    m_waitStackRange.StartFrame();
    m_memInfo.range.StartFrame();
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
        HandleRange( m_findZone.range, timespan, ImGui::GetCursorScreenPos(), w );
        HandleRange( m_statRange, timespan, ImGui::GetCursorScreenPos(), w );
        HandleRange( m_waitStackRange, timespan, ImGui::GetCursorScreenPos(), w );
        HandleRange( m_memInfo.range, timespan, ImGui::GetCursorScreenPos(), w );
        for( auto& v : m_annotations )
        {
            v->range.StartFrame();
            HandleRange( v->range, timespan, ImGui::GetCursorScreenPos(), w );
        }
        HandleTimelineMouse( timespan, ImGui::GetCursorScreenPos(), w, pxns );
    }
    if( ImGui::IsWindowFocused( ImGuiHoveredFlags_ChildWindows | ImGuiHoveredFlags_AllowWhenBlockedByActiveItem ) )
    {
        HandleTimelineKeyboard( timespan, ImGui::GetCursorScreenPos(), w );
    }

    {
        const auto tbegin = 0;
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

    const auto yMin = ImGui::GetCursorScreenPos().y;
    const auto yMax = linepos.y + lineh;

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

    const auto ty = ImGui::GetTextLineHeight();
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;

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
        const auto& threadData = m_worker.GetThreadData();
        if( threadData.size() != m_threadOrder.size() )
        {
            m_threadOrder.reserve( threadData.size() );
            for( size_t i=m_threadOrder.size(); i<threadData.size(); i++ )
            {
                m_threadOrder.push_back( threadData[i] );
            }
        }
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

    for( auto& ann : m_annotations )
    {
        if( ann->range.min < m_vd.zvEnd && ann->range.max > m_vd.zvStart )
        {
            uint32_t c0 = ( ann->color & 0xFFFFFF ) | ( m_selectedAnnotation == ann.get() ? 0x44000000 : 0x22000000 );
            uint32_t c1 = ( ann->color & 0xFFFFFF ) | ( m_selectedAnnotation == ann.get() ? 0x66000000 : 0x44000000 );
            uint32_t c2 = ( ann->color & 0xFFFFFF ) | ( m_selectedAnnotation == ann.get() ? 0xCC000000 : 0xAA000000 );
            draw->AddRectFilled( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns, 0 ), linepos + ImVec2( ( ann->range.max - m_vd.zvStart ) * pxns, lineh ), c0 );
            DrawLine( draw, linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + 0.5f, 0.5f ), linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + 0.5f, lineh + 0.5f ), ann->range.hiMin ? c2 : c1, ann->range.hiMin ? 2 : 1 );
            DrawLine( draw, linepos + ImVec2( ( ann->range.max - m_vd.zvStart ) * pxns + 0.5f, 0.5f ), linepos + ImVec2( ( ann->range.max - m_vd.zvStart ) * pxns + 0.5f, lineh + 0.5f ), ann->range.hiMax ? c2 : c1, ann->range.hiMax ? 2 : 1 );
            if( drawMouseLine && ImGui::IsMouseHoveringRect( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns, 0 ), linepos + ImVec2( ( ann->range.max - m_vd.zvStart ) * pxns, lineh ) ) )
            {
                ImGui::BeginTooltip();
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
            if( aw > th * 4 )
            {
                draw->AddCircleFilled( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th * 2, th * 2 ), th, 0x88AABB22 );
                draw->AddCircle( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th * 2, th * 2 ), th, 0xAAAABB22 );
                if( drawMouseLine && IsMouseClicked( 0 ) && ImGui::IsMouseHoveringRect( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th, th ), linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th * 3, th * 3 ) ) )
                {
                    m_selectedAnnotation = ann.get();
                }

                if( !ann->text.empty() )
                {
                    const auto tw = ImGui::CalcTextSize( ann->text.c_str() ).x;
                    if( aw - th*4 > tw )
                    {
                        draw->AddText( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th * 4, th * 0.5 ), 0xFFFFFFFF, ann->text.c_str() );
                    }
                    else
                    {
                        draw->PushClipRect( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns, 0 ), linepos + ImVec2( ( ann->range.max - m_vd.zvStart ) * pxns, lineh ), true );
                        draw->AddText( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th * 4, th * 0.5 ), 0xFFFFFFFF, ann->text.c_str() );
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

    const auto scale = GetScale();
    if( m_findZone.range.active && ( m_findZone.show || m_showRanges ) )
    {
        const auto px0 = ( m_findZone.range.min - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_findZone.range.max - m_vd.zvStart ) * pxns );
        DrawStripedRect( draw, wpos, px0, linepos.y, px1, linepos.y + lineh, 10 * scale, 0x2288DD88, true, true );
        DrawLine( draw, ImVec2( dpos.x + px0, linepos.y + 0.5f ), ImVec2( dpos.x + px0, linepos.y + lineh + 0.5f ), m_findZone.range.hiMin ? 0x9988DD88 : 0x3388DD88, m_findZone.range.hiMin ? 2 : 1 );
        DrawLine( draw, ImVec2( dpos.x + px1, linepos.y + 0.5f ), ImVec2( dpos.x + px1, linepos.y + lineh + 0.5f ), m_findZone.range.hiMax ? 0x9988DD88 : 0x3388DD88, m_findZone.range.hiMax ? 2 : 1 );
    }

    if( m_statRange.active && ( m_showStatistics || m_showRanges || ( m_sourceViewFile && m_sourceView->IsSymbolView() ) ) )
    {
        const auto px0 = ( m_statRange.min - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_statRange.max - m_vd.zvStart ) * pxns );
        DrawStripedRect( draw, wpos, px0, linepos.y, px1, linepos.y + lineh, 10 * scale, 0x228888EE, true, false );
        DrawLine( draw, ImVec2( dpos.x + px0, linepos.y + 0.5f ), ImVec2( dpos.x + px0, linepos.y + lineh + 0.5f ), m_statRange.hiMin ? 0x998888EE : 0x338888EE, m_statRange.hiMin ? 2 : 1 );
        DrawLine( draw, ImVec2( dpos.x + px1, linepos.y + 0.5f ), ImVec2( dpos.x + px1, linepos.y + lineh + 0.5f ), m_statRange.hiMax ? 0x998888EE : 0x338888EE, m_statRange.hiMax ? 2 : 1 );
    }

    if( m_waitStackRange.active && ( m_showWaitStacks || m_showRanges ) )
    {
        const auto px0 = ( m_waitStackRange.min - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_waitStackRange.max - m_vd.zvStart ) * pxns );
        DrawStripedRect( draw, wpos, px0, linepos.y, px1, linepos.y + lineh, 10 * scale, 0x22EEB588, true, true );
        DrawLine( draw, ImVec2( dpos.x + px0, linepos.y + 0.5f ), ImVec2( dpos.x + px0, linepos.y + lineh + 0.5f ), m_waitStackRange.hiMin ? 0x99EEB588 : 0x33EEB588, m_waitStackRange.hiMin ? 2 : 1 );
        DrawLine( draw, ImVec2( dpos.x + px1, linepos.y + 0.5f ), ImVec2( dpos.x + px1, linepos.y + lineh + 0.5f ), m_waitStackRange.hiMax ? 0x99EEB588 : 0x33EEB588, m_waitStackRange.hiMax ? 2 : 1 );
    }

    if( m_memInfo.range.active && ( m_memInfo.show || m_showRanges ) )
    {
        const auto px0 = ( m_memInfo.range.min - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_memInfo.range.max - m_vd.zvStart ) * pxns );
        DrawStripedRect( draw, wpos, px0, linepos.y, px1, linepos.y + lineh, 10 * scale, 0x2288EEE3, true, false );
        DrawLine( draw, ImVec2( dpos.x + px0, linepos.y + 0.5f ), ImVec2( dpos.x + px0, linepos.y + lineh + 0.5f ), m_memInfo.range.hiMin ? 0x9988EEE3 : 0x3388EEE3, m_memInfo.range.hiMin ? 2 : 1 );
        DrawLine( draw, ImVec2( dpos.x + px1, linepos.y + 0.5f ), ImVec2( dpos.x + px1, linepos.y + lineh + 0.5f ), m_memInfo.range.hiMax ? 0x9988EEE3 : 0x3388EEE3, m_memInfo.range.hiMax ? 2 : 1 );
    }

    if( m_setRangePopup.active || m_setRangePopupOpen )
    {
        const auto s = std::min( m_setRangePopup.min, m_setRangePopup.max );
        const auto e = std::max( m_setRangePopup.min, m_setRangePopup.max );
        DrawStripedRect( draw, wpos, ( s - m_vd.zvStart ) * pxns, linepos.y, ( e - m_vd.zvStart ) * pxns, linepos.y + lineh, 5 * scale, 0x55DD8888, true, false );
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
