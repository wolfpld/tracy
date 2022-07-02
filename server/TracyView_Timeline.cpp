#include <algorithm>

#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracySourceView.hpp"
#include "TracyView.hpp"

namespace tracy
{

enum { MinVisSize = 3 };

extern double s_time;

float View::AdjustThreadPosition( View::VisData& vis, float wy, int& offset )
{
    if( vis.offset < offset )
    {
        vis.offset = offset;
    }
    else if( vis.offset > offset )
    {
        const auto diff = vis.offset - offset;
        const auto move = std::max( 2.0, diff * 10.0 * ImGui::GetIO().DeltaTime );
        offset = vis.offset = int( std::max<double>( vis.offset - move, offset ) );
    }

    return offset + wy;
}

void View::AdjustThreadHeight( View::VisData& vis, int oldOffset, int& offset )
{
    const auto h = offset - oldOffset;
    if( vis.height > h )
    {
        vis.height = h;
        offset = oldOffset + vis.height;
    }
    else if( vis.height < h )
    {
        if( m_firstFrame )
        {
            vis.height = h;
            offset = oldOffset + h;
        }
        else
        {
            const auto diff = h - vis.height;
            const auto move = std::max( 2.0, diff * 10.0 * ImGui::GetIO().DeltaTime );
            vis.height = int( std::min<double>( vis.height + move, h ) );
            offset = oldOffset + vis.height;
        }
    }
}

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

    DrawTimelineFramesHeader();
    auto& frames = m_worker.GetFrames();
    for( auto fd : frames )
    {
        if( Vis( fd ).visible )
        {
            DrawTimelineFrames( *fd );
        }
    }

    const auto yMin = ImGui::GetCursorScreenPos().y;
    const auto yMax = linepos.y + lineh;

    ImGui::BeginChild( "##zoneWin", ImVec2( ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y ), false, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_NoScrollWithMouse );

    if( m_yDelta != 0 )
    {
        auto& io = ImGui::GetIO();
        auto y = ImGui::GetScrollY();
        ImGui::SetScrollY( y - m_yDelta );
        io.MouseClickedPos[1].y = io.MousePos.y;
    }

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto h = std::max<float>( m_vd.zvHeight, ImGui::GetContentRegionAvail().y - 4 );    // magic border value

    ImGui::InvisibleButton( "##zones", ImVec2( w, h ) );
    bool hover = ImGui::IsItemHovered();
    draw = ImGui::GetWindowDrawList();

    const auto nspx = 1.0 / pxns;

    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    int offset = 0;
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;

    // gpu zones
    if( m_vd.drawGpuZones )
    {
        for( size_t i=0; i<m_worker.GetGpuData().size(); i++ )
        {
            const auto& v = m_worker.GetGpuData()[i];
            auto& vis = Vis( v );
            if( !vis.visible )
            {
                vis.height = 0;
                vis.offset = 0;
                continue;
            }
            bool& showFull = vis.showFull;

            const auto yPos = AdjustThreadPosition( vis, wpos.y, offset );
            const auto oldOffset = offset;
            ImGui::PushClipRect( wpos, wpos + ImVec2( w, oldOffset + vis.height ), true );

            ImGui::PushFont( m_smallFont );
            const auto sty = ImGui::GetTextLineHeight();
            const auto sstep = sty + 1;
            ImGui::PopFont();

            const auto singleThread = v->threadData.size() == 1;
            int depth = 0;
            offset += ostep;
            if( showFull && !v->threadData.empty() )
            {
                for( auto& td : v->threadData )
                {
                    auto& tl = td.second.timeline;
                    assert( !tl.empty() );
                    if( tl.is_magic() )
                    {
                        auto& tlm = *(Vector<GpuEvent>*)&tl;
                        if( tlm.front().GpuStart() >= 0 )
                        {
                            const auto begin = tlm.front().GpuStart();
                            const auto drift = GpuDrift( v );
                            if( !singleThread ) offset += sstep;
                            const auto partDepth = DispatchGpuZoneLevel( tl, hover, pxns, int64_t( nspx ), wpos, offset, 0, v->thread, yMin, yMax, begin, drift );
                            if( partDepth != 0 )
                            {
                                if( !singleThread )
                                {
                                    ImGui::PushFont( m_smallFont );
                                    DrawTextContrast( draw, wpos + ImVec2( ty, offset-1-sstep ), 0xFFFFAAAA, m_worker.GetThreadName( td.first ) );
                                    DrawLine( draw, dpos + ImVec2( 0, offset+sty-sstep ), dpos + ImVec2( w, offset+sty-sstep ), 0x22FFAAAA );
                                    ImGui::PopFont();
                                }

                                offset += ostep * partDepth;
                                depth += partDepth;
                            }
                            else if( !singleThread )
                            {
                                offset -= sstep;
                            }
                        }
                    }
                    else
                    {
                        if( tl.front()->GpuStart() >= 0 )
                        {
                            const auto begin = tl.front()->GpuStart();
                            const auto drift = GpuDrift( v );
                            if( !singleThread ) offset += sstep;
                            const auto partDepth = DispatchGpuZoneLevel( tl, hover, pxns, int64_t( nspx ), wpos, offset, 0, v->thread, yMin, yMax, begin, drift );
                            if( partDepth != 0 )
                            {
                                if( !singleThread )
                                {
                                    ImGui::PushFont( m_smallFont );
                                    DrawTextContrast( draw, wpos + ImVec2( ty, offset-1-sstep ), 0xFFFFAAAA, m_worker.GetThreadName( td.first ) );
                                    DrawLine( draw, dpos + ImVec2( 0, offset+sty-sstep ), dpos + ImVec2( w, offset+sty-sstep ), 0x22FFAAAA );
                                    ImGui::PopFont();
                                }

                                offset += ostep * partDepth;
                                depth += partDepth;
                            }
                            else if( !singleThread )
                            {
                                offset -= sstep;
                            }
                        }
                    }
                }
            }
            offset += ostep * 0.2f;

            if( !m_vd.drawEmptyLabels && showFull && depth == 0 )
            {
                vis.height = 0;
                vis.offset = 0;
                offset = oldOffset;
            }
            else if( yPos + ostep >= yMin && yPos <= yMax )
            {
                DrawLine( draw, dpos + ImVec2( 0, oldOffset + ostep - 1 ), dpos + ImVec2( w, oldOffset + ostep - 1 ), 0x33FFFFFF );

                if( showFull )
                {
                    draw->AddTriangleFilled( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( ty - to/2, oldOffset + to/2 ), wpos + ImVec2( ty * 0.5, oldOffset + to/2 + th ), 0xFFFFAAAA );
                }
                else
                {
                    draw->AddTriangle( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( to/2, oldOffset + ty - to/2 ), wpos + ImVec2( to/2 + th, oldOffset + ty * 0.5 ), 0xFF886666, 2.0f );
                }

                const bool isMultithreaded = (v->type == GpuContextType::Vulkan) || (v->type == GpuContextType::OpenCL) || (v->type == GpuContextType::Direct3D12);

                float boxwidth;
                char buf[64];
                sprintf( buf, "%s context %zu", GpuContextNames[(int)v->type], i );
                if( v->name.Active() )
                {
                    char tmp[4096];
                    sprintf( tmp, "%s: %s", buf, m_worker.GetString( v->name ) );
                    DrawTextContrast( draw, wpos + ImVec2( ty, oldOffset ), showFull ? 0xFFFFAAAA : 0xFF886666, tmp );
                    boxwidth = ImGui::CalcTextSize( tmp ).x;
                }
                else
                {
                    DrawTextContrast( draw, wpos + ImVec2( ty, oldOffset ), showFull ? 0xFFFFAAAA : 0xFF886666, buf );
                    boxwidth = ImGui::CalcTextSize( buf ).x;
                }

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( ty + boxwidth, oldOffset + ty ) ) )
                {
                    if( IsMouseClicked( 0 ) )
                    {
                        showFull = !showFull;
                    }
                    if( IsMouseClicked( 2 ) )
                    {
                        int64_t t0 = std::numeric_limits<int64_t>::max();
                        int64_t t1 = std::numeric_limits<int64_t>::min();
                        for( auto& td : v->threadData )
                        {
                            int64_t _t0;
                            if( td.second.timeline.is_magic() )
                            {
                                _t0 = ((Vector<GpuEvent>*)&td.second.timeline)->front().GpuStart();
                            }
                            else
                            {
                                _t0 = td.second.timeline.front()->GpuStart();
                            }
                            if( _t0 >= 0 )
                            {
                                // FIXME
                                t0 = std::min( t0, _t0 );
                                if( td.second.timeline.is_magic() )
                                {
                                    t1 = std::max( t1, std::min( m_worker.GetLastTime(), m_worker.GetZoneEnd( ((Vector<GpuEvent>*)&td.second.timeline)->back() ) ) );
                                }
                                else
                                {
                                    t1 = std::max( t1, std::min( m_worker.GetLastTime(), m_worker.GetZoneEnd( *td.second.timeline.back() ) ) );
                                }
                            }
                        }
                        if( t0 < t1 )
                        {
                            ZoomToRange( t0, t1 );
                        }
                    }

                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted( buf );
                    if( v->name.Active() ) TextFocused( "Name:", m_worker.GetString( v->name ) );
                    ImGui::Separator();
                    if( !isMultithreaded )
                    {
                        SmallColorBox( GetThreadColor( v->thread, 0 ) );
                        ImGui::SameLine();
                        TextFocused( "Thread:", m_worker.GetThreadName( v->thread ) );
                    }
                    else
                    {
                        if( !v->threadData.empty() )
                        {
                            if( v->threadData.size() == 1 )
                            {
                                auto it = v->threadData.begin();
                                auto tid = it->first;
                                if( tid == 0 )
                                {
                                    if( !it->second.timeline.empty() )
                                    {
                                        if( it->second.timeline.is_magic() )
                                        {
                                            auto& tl = *(Vector<GpuEvent>*)&it->second.timeline;
                                            tid = m_worker.DecompressThread( tl.begin()->Thread() );
                                        }
                                        else
                                        {
                                            tid = m_worker.DecompressThread( (*it->second.timeline.begin())->Thread() );
                                        }
                                    }
                                }
                                SmallColorBox( GetThreadColor( tid, 0 ) );
                                ImGui::SameLine();
                                TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
                                ImGui::SameLine();
                                ImGui::TextDisabled( "(%s)", RealToString( tid ) );
                                if( m_worker.IsThreadFiber( tid ) )
                                {
                                    ImGui::SameLine();
                                    TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
                                }
                            }
                            else
                            {
                                ImGui::TextDisabled( "Threads:" );
                                ImGui::Indent();
                                for( auto& td : v->threadData )
                                {
                                    SmallColorBox( GetThreadColor( td.first, 0 ) );
                                    ImGui::SameLine();
                                    ImGui::TextUnformatted( m_worker.GetThreadName( td.first ) );
                                    ImGui::SameLine();
                                    ImGui::TextDisabled( "(%s)", RealToString( td.first ) );
                                }
                                ImGui::Unindent();
                            }
                        }
                    }
                    if( !v->threadData.empty() )
                    {
                        int64_t t0 = std::numeric_limits<int64_t>::max();
                        for( auto& td : v->threadData )
                        {
                            int64_t _t0;
                            if( td.second.timeline.is_magic() )
                            {
                                _t0 = ((Vector<GpuEvent>*)&td.second.timeline)->front().GpuStart();
                            }
                            else
                            {
                                _t0 = td.second.timeline.front()->GpuStart();
                            }
                            if( _t0 >= 0 )
                            {
                                t0 = std::min( t0, _t0 );
                            }
                        }
                        if( t0 != std::numeric_limits<int64_t>::max() )
                        {
                            TextFocused( "Appeared at", TimeToString( t0 ) );
                        }
                    }
                    TextFocused( "Zone count:", RealToString( v->count ) );
                    if( v->period != 1.f )
                    {
                        TextFocused( "Timestamp accuracy:", TimeToString( v->period ) );
                    }
                    if( v->overflow != 0 )
                    {
                        ImGui::Separator();
                        ImGui::TextUnformatted( "GPU timer overflow has been detected." );
                        TextFocused( "Timer resolution:", RealToString( 63 - TracyLzcnt( v->overflow ) ) );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "bits" );
                    }
                    ImGui::EndTooltip();
                }
            }

            AdjustThreadHeight( vis, oldOffset, offset );
            ImGui::PopClipRect();
        }
    }

    // zones
    if( m_vd.drawCpuData && m_worker.HasContextSwitches() )
    {
        offset = DrawCpuData( offset, pxns, wpos, hover, yMin, yMax );
    }

    const auto& threadData = m_worker.GetThreadData();
    if( threadData.size() != m_threadOrder.size() )
    {
        m_threadOrder.reserve( threadData.size() );
        for( size_t i=m_threadOrder.size(); i<threadData.size(); i++ )
        {
            m_threadOrder.push_back( threadData[i] );
        }
    }

    auto& crash = m_worker.GetCrashEvent();
    LockHighlight nextLockHighlight { -1 };
    for( const auto& v : m_threadOrder )
    {
        auto& vis = Vis( v );
        if( !vis.visible )
        {
            vis.height = 0;
            vis.offset = 0;
            continue;
        }
        bool showFull = vis.showFull;

        const auto yPos = AdjustThreadPosition( vis, wpos.y, offset );
        const auto oldOffset = offset;
        ImGui::PushClipRect( wpos, wpos + ImVec2( w, offset + vis.height ), true );

        int depth = 0;
        offset += ostep;
        if( showFull )
        {
            const auto sampleOffset = offset;
            const auto hasSamples = m_vd.drawSamples && !v->samples.empty();
            const auto hasCtxSwitch = m_vd.drawContextSwitches && m_worker.GetContextSwitchData( v->id );

            if( hasSamples )
            {
                if( hasCtxSwitch )
                {
                    offset += round( ostep * 0.5f );
                }
                else
                {
                    offset += round( ostep * 0.75f );
                }
            }

            const auto ctxOffset = offset;
            if( hasCtxSwitch ) offset += round( ostep * 0.75f );

            if( m_vd.drawZones )
            {
#ifndef TRACY_NO_STATISTICS
                if( m_worker.AreGhostZonesReady() && ( vis.ghost || ( m_vd.ghostZones && v->timeline.empty() ) ) )
                {
                    depth = DispatchGhostLevel( v->ghostZones, hover, pxns, int64_t( nspx ), wpos, offset, 0, yMin, yMax, v->id );
                }
                else
#endif
                {
                    depth = DispatchZoneLevel( v->timeline, hover, pxns, int64_t( nspx ), wpos, offset, 0, yMin, yMax, v->id );
                }
                offset += ostep * depth;
            }

            if( hasCtxSwitch )
            {
                auto ctxSwitch = m_worker.GetContextSwitchData( v->id );
                if( ctxSwitch )
                {
                    DrawContextSwitches( ctxSwitch, v->samples, hover, pxns, int64_t( nspx ), wpos, ctxOffset, offset, v->isFiber );
                }
            }

            if( hasSamples )
            {
                DrawSamples( v->samples, hover, pxns, int64_t( nspx ), wpos, sampleOffset );
            }

            if( m_vd.drawLocks )
            {
                const auto lockDepth = DrawLocks( v->id, hover, pxns, wpos, offset, nextLockHighlight, yMin, yMax );
                offset += ostep * lockDepth;
                depth += lockDepth;
            }
        }
        offset += ostep * 0.2f;

        auto msgit = std::lower_bound( v->messages.begin(), v->messages.end(), m_vd.zvStart, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
        auto msgend = std::lower_bound( msgit, v->messages.end(), m_vd.zvEnd+1, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );

        if( !m_vd.drawEmptyLabels && showFull && depth == 0 && msgit == msgend && crash.thread != v->id )
        {
            auto& vis = Vis( v );
            vis.height = 0;
            vis.offset = 0;
            offset = oldOffset;
        }
        else if( yPos + ostep >= yMin && yPos <= yMax )
        {
            DrawLine( draw, dpos + ImVec2( 0, oldOffset + ostep - 1 ), dpos + ImVec2( w, oldOffset + ostep - 1 ), 0x33FFFFFF );

            uint32_t labelColor;
            if( crash.thread == v->id ) labelColor = showFull ? 0xFF2222FF : 0xFF111188;
            else if( v->isFiber ) labelColor = showFull ? 0xFF88FF88 : 0xFF448844;
            else labelColor = showFull ? 0xFFFFFFFF : 0xFF888888;

            if( showFull )
            {
                draw->AddTriangleFilled( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( ty - to/2, oldOffset + to/2 ), wpos + ImVec2( ty * 0.5, oldOffset + to/2 + th ), labelColor );

                while( msgit < msgend )
                {
                    const auto next = std::upper_bound( msgit, v->messages.end(), (*msgit)->time + MinVisSize * nspx, [] ( const auto& lhs, const auto& rhs ) { return lhs < rhs->time; } );
                    const auto dist = std::distance( msgit, next );

                    const auto px = ( (*msgit)->time - m_vd.zvStart ) * pxns;
                    const bool isMsgHovered = hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, oldOffset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, oldOffset + ty ) );

                    unsigned int color = 0xFFDDDDDD;
                    float animOff = 0;
                    if( dist > 1 )
                    {
                        if( m_msgHighlight && m_worker.DecompressThread( m_msgHighlight->thread ) == v->id )
                        {
                            const auto hTime = m_msgHighlight->time;
                            if( (*msgit)->time <= hTime && ( next == v->messages.end() || (*next)->time > hTime ) )
                            {
                                color = 0xFF4444FF;
                                if( !isMsgHovered )
                                {
                                    animOff = -fabs( sin( s_time * 8 ) ) * th;
                                }
                            }
                        }
                        draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px + (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px, animOff + oldOffset + to + th ), color );
                        draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px + (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px, animOff + oldOffset + to + th ), color, 2.0f );
                    }
                    else
                    {
                        if( m_msgHighlight == *msgit )
                        {
                            color = 0xFF4444FF;
                            if( !isMsgHovered )
                            {
                                animOff = -fabs( sin( s_time * 8 ) ) * th;
                            }
                        }
                        draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px + (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px, animOff + oldOffset + to + th ), color, 2.0f );
                    }
                    if( isMsgHovered )
                    {
                        ImGui::BeginTooltip();
                        if( dist > 1 )
                        {
                            ImGui::Text( "%i messages", (int)dist );
                        }
                        else
                        {
                            TextFocused( "Message at", TimeToStringExact( (*msgit)->time ) );
                            ImGui::PushStyleColor( ImGuiCol_Text, (*msgit)->color );
                            ImGui::TextUnformatted( m_worker.GetString( (*msgit)->ref ) );
                            ImGui::PopStyleColor();
                        }
                        ImGui::EndTooltip();
                        m_msgHighlight = *msgit;

                        if( IsMouseClicked( 0 ) )
                        {
                            m_showMessages = true;
                            m_msgToFocus = *msgit;
                        }
                        if( IsMouseClicked( 2 ) )
                        {
                            CenterAtTime( (*msgit)->time );
                        }
                    }
                    msgit = next;
                }

                if( crash.thread == v->id && crash.time >= m_vd.zvStart && crash.time <= m_vd.zvEnd )
                {
                    const auto px = ( crash.time - m_vd.zvStart ) * pxns;

                    draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px + (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px, oldOffset + to + th ), 0xFF2222FF );
                    draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px + (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px, oldOffset + to + th ), 0xFF2222FF, 2.0f );

                    const auto crashText = ICON_FA_SKULL " crash " ICON_FA_SKULL;
                    auto ctw = ImGui::CalcTextSize( crashText ).x;
                    DrawTextContrast( draw, wpos + ImVec2( px - ctw * 0.5f, oldOffset + to + th * 0.5f - ty ), 0xFF2222FF, crashText );

                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, oldOffset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, oldOffset + ty ) ) )
                    {
                        CrashTooltip();
                        if( IsMouseClicked( 0 ) )
                        {
                            m_showInfo = true;
                        }
                        if( IsMouseClicked( 2 ) )
                        {
                            CenterAtTime( crash.time );
                        }
                    }
                }
            }
            else
            {
                draw->AddTriangle( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( to/2, oldOffset + ty - to/2 ), wpos + ImVec2( to/2 + th, oldOffset + ty * 0.5 ), labelColor, 2.0f );
            }
            const auto txt = m_worker.GetThreadName( v->id );
            const auto txtsz = ImGui::CalcTextSize( txt );
            if( m_gpuThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x228888DD );
                draw->AddRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x448888DD );
            }
            if( m_gpuInfoWindow && m_gpuInfoWindowThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x2288DD88 );
                draw->AddRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x4488DD88 );
            }
            if( m_cpuDataThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x2DFF8888 );
                draw->AddRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x4DFF8888 );
            }
            DrawTextContrast( draw, wpos + ImVec2( ty, oldOffset ), labelColor, txt );

#ifndef TRACY_NO_STATISTICS
            const bool hasGhostZones = showFull && m_worker.AreGhostZonesReady() && !v->ghostZones.empty();
            float ghostSz;
            if( hasGhostZones && !v->timeline.empty() )
            {
                auto& vis = Vis( v );
                const auto color = vis.ghost ? 0xFFAA9999 : 0x88AA7777;
                draw->AddText( wpos + ImVec2( 1.5f * ty + txtsz.x, oldOffset ), color, ICON_FA_GHOST );
                ghostSz = ImGui::CalcTextSize( ICON_FA_GHOST ).x;
            }
#endif

            if( hover )
            {
#ifndef TRACY_NO_STATISTICS
                if( hasGhostZones && !v->timeline.empty() && ImGui::IsMouseHoveringRect( wpos + ImVec2( 1.5f * ty + txtsz.x, oldOffset ), wpos + ImVec2( 1.5f * ty + txtsz.x + ghostSz, oldOffset + ty ) ) )
                {
                    if( IsMouseClicked( 0 ) )
                    {
                        auto& vis = Vis( v );
                        vis.ghost = !vis.ghost;
                    }
                }
                else
#endif
                    if( ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( ty + txtsz.x, oldOffset + ty ) ) )
                    {
                        m_drawThreadMigrations = v->id;
                        m_drawThreadHighlight = v->id;
                        ImGui::BeginTooltip();
                        SmallColorBox( GetThreadColor( v->id, 0 ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( m_worker.GetThreadName( v->id ) );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%s)", RealToString( v->id ) );
                        if( crash.thread == v->id )
                        {
                            ImGui::SameLine();
                            TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
                        }
                        if( v->isFiber )
                        {
                            ImGui::SameLine();
                            TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
                        }

                        const auto ctx = m_worker.GetContextSwitchData( v->id );

                        ImGui::Separator();
                        int64_t first = std::numeric_limits<int64_t>::max();
                        int64_t last = -1;
                        if( ctx && !ctx->v.empty() )
                        {
                            const auto& back = ctx->v.back();
                            first = ctx->v.begin()->Start();
                            last = back.IsEndValid() ? back.End() : back.Start();
                        }
                        if( !v->timeline.empty() )
                        {
                            if( v->timeline.is_magic() )
                            {
                                auto& tl = *((Vector<ZoneEvent>*)&v->timeline);
                                first = std::min( first, tl.front().Start() );
                                last = std::max( last, m_worker.GetZoneEnd( tl.back() ) );
                            }
                            else
                            {
                                first = std::min( first, v->timeline.front()->Start() );
                                last = std::max( last, m_worker.GetZoneEnd( *v->timeline.back() ) );
                            }
                        }
                        if( !v->messages.empty() )
                        {
                            first = std::min( first, v->messages.front()->time );
                            last = std::max( last, v->messages.back()->time );
                        }
                        size_t lockCnt = 0;
                        for( const auto& lock : m_worker.GetLockMap() )
                        {
                            const auto& lockmap = *lock.second;
                            if( !lockmap.valid ) continue;
                            auto it = lockmap.threadMap.find( v->id );
                            if( it == lockmap.threadMap.end() ) continue;
                            lockCnt++;
                            const auto thread = it->second;
                            auto lptr = lockmap.timeline.data();
                            auto eptr = lptr + lockmap.timeline.size() - 1;
                            while( lptr->ptr->thread != thread ) lptr++;
                            if( lptr->ptr->Time() < first ) first = lptr->ptr->Time();
                            while( eptr->ptr->thread != thread ) eptr--;
                            if( eptr->ptr->Time() > last ) last = eptr->ptr->Time();
                        }

                        if( last >= 0 )
                        {
                            const auto lifetime = last - first;
                            const auto traceLen = m_worker.GetLastTime();

                            TextFocused( "Appeared at", TimeToString( first ) );
                            TextFocused( "Last event at", TimeToString( last ) );
                            TextFocused( "Lifetime:", TimeToString( lifetime ) );
                            ImGui::SameLine();
                            char buf[64];
                            PrintStringPercent( buf, lifetime / double( traceLen ) * 100 );
                            TextDisabledUnformatted( buf );

                            if( ctx )
                            {
                                TextFocused( "Time in running state:", TimeToString( ctx->runningTime ) );
                                ImGui::SameLine();
                                PrintStringPercent( buf, ctx->runningTime / double( lifetime ) * 100 );
                                TextDisabledUnformatted( buf );
                            }
                        }

                        ImGui::Separator();
                        if( !v->timeline.empty() )
                        {
                            TextFocused( "Zone count:", RealToString( v->count ) );
                            TextFocused( "Top-level zones:", RealToString( v->timeline.size() ) );
                        }
                        if( !v->messages.empty() )
                        {
                            TextFocused( "Messages:", RealToString( v->messages.size() ) );
                        }
                        if( lockCnt != 0 )
                        {
                            TextFocused( "Locks:", RealToString( lockCnt ) );
                        }
                        if( ctx )
                        {
                            TextFocused( "Running state regions:", RealToString( ctx->v.size() ) );
                        }
                        if( !v->samples.empty() )
                        {
                            TextFocused( "Call stack samples:", RealToString( v->samples.size() ) );
                            if( v->kernelSampleCnt != 0 )
                            {
                                TextFocused( "Kernel samples:", RealToString( v->kernelSampleCnt ) );
                                ImGui::SameLine();
                                ImGui::TextDisabled( "(%.2f%%)", 100.f * v->kernelSampleCnt / v->samples.size() );
                            }
                        }
                        ImGui::EndTooltip();

                        if( IsMouseClicked( 0 ) )
                        {
                            Vis( v ).showFull = !showFull;
                        }
                        if( last >= 0 && IsMouseClicked( 2 ) )
                        {
                            ZoomToRange( first, last );
                        }
                    }
            }
        }

        AdjustThreadHeight( Vis( v ), oldOffset, offset );
        ImGui::PopClipRect();
    }
    m_lockHighlight = nextLockHighlight;

    if( m_vd.drawPlots )
    {
        offset = DrawPlots( offset, pxns, wpos, hover, yMin, yMax );
    }

    const auto scrollPos = ImGui::GetScrollY();
    if( scrollPos == 0 && m_vd.zvScroll != 0 )
    {
        m_vd.zvHeight = 0;
    }
    else
    {
        if( offset > m_vd.zvHeight ) m_vd.zvHeight = offset;
    }
    m_vd.zvScroll = scrollPos;

    ImGui::EndChild();

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
