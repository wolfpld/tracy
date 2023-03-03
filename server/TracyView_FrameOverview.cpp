#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTexture.hpp"
#include "TracyView.hpp"

namespace tracy
{

static uint32_t GetFrameColor( uint64_t time, uint64_t target )
{
    return time > target * 2 ? 0xFF2222DD :
           time > target     ? 0xFF22DDDD :
           time > target / 2 ? 0xFF22DD22 : 0xFFDD9900;
}

static int GetFrameWidth( int frameScale )
{
    return frameScale == 0 ? 4 : ( frameScale < 0 ? 6 : 1 );
}

static int GetFrameGroup( int frameScale )
{
    return frameScale < 2 ? 1 : ( 1 << ( frameScale - 1 ) );
}

template<class T>
constexpr const T& clamp( const T& v, const T& lo, const T& hi )
{
    return v < lo ? lo : v > hi ? hi : v;
}

void View::DrawFrames()
{
    assert( m_worker.GetFrameCount( *m_frames ) != 0 );

    const auto scale = GetScale();
    const auto Height = 50 * scale;

    constexpr uint64_t MaxFrameTime = 50 * 1000 * 1000;  // 50ms

    ImGuiWindow* window = ImGui::GetCurrentWindowRead();
    if( window->SkipItems ) return;

    const uint64_t frameTarget = 1000 * 1000 * 1000 / m_vd.frameTarget;

    auto& io = ImGui::GetIO();

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto wspace = ImGui::GetWindowContentRegionMax() - ImGui::GetWindowContentRegionMin();
    const auto w = wspace.x;
    auto draw = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton( "##frames", ImVec2( w, Height ) );
    bool hover = ImGui::IsItemHovered();

    draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x33FFFFFF );
    const auto wheel = io.MouseWheel;
    const auto prevScale = m_vd.frameScale;
    if( hover )
    {
        if( wheel > 0 )
        {
            if( m_vd.frameScale >= 0 ) m_vd.frameScale--;
        }
        else if( wheel < 0 )
        {
            if( m_vd.frameScale < 10 ) m_vd.frameScale++;
        }
    }

    const int fwidth = GetFrameWidth( m_vd.frameScale );
    const int group = GetFrameGroup( m_vd.frameScale );
    const int total = m_worker.GetFrameCount( *m_frames );
    const int onScreen = ( w - 2 ) / fwidth;
    if( m_viewMode != ViewMode::Paused )
    {
        m_vd.frameStart = ( total < onScreen * group ) ? 0 : total - onScreen * group;
        if( m_viewMode == ViewMode::LastFrames )
        {
            SetViewToLastFrames();
        }
        else
        {
            assert( m_viewMode == ViewMode::LastRange );
            const auto delta = m_worker.GetLastTime() - m_vd.zvEnd;
            if( delta != 0 )
            {
                m_vd.zvStart += delta;
                m_vd.zvEnd += delta;
            }
        }
    }

    if( hover )
    {
        const auto hwheel_delta = io.MouseWheelH * 100.f;
        if( IsMouseDragging( 1 ) || hwheel_delta != 0 )
        {
            m_viewMode = ViewMode::Paused;
            m_viewModeHeuristicTry = false;
            auto delta = GetMouseDragDelta( 1 ).x;
            if( delta == 0 ) delta = hwheel_delta;
            if( abs( delta ) >= fwidth )
            {
                const auto d = (int)delta / fwidth;
                m_vd.frameStart = std::max( 0, m_vd.frameStart - d * group );
                io.MouseClickedPos[1].x = io.MousePos.x + d * fwidth - delta;
            }
        }

        const auto mx = io.MousePos.x;
        if( mx > wpos.x && mx < wpos.x + w - 1 )
        {
            const auto mo = mx - ( wpos.x + 1 );
            const auto off = mo * group / fwidth;

            const int sel = m_vd.frameStart + off;
            if( sel < total )
            {
                ImGui::BeginTooltip();
                if( group > 1 )
                {
                    auto f = m_worker.GetFrameTime( *m_frames, sel );
                    auto g = std::min( group, total - sel );
                    for( int j=1; j<g; j++ )
                    {
                        f = std::max( f, m_worker.GetFrameTime( *m_frames, sel + j ) );
                    }

                    TextDisabledUnformatted( "Frames:" );
                    ImGui::SameLine();
                    ImGui::Text( "%s - %s (%s)", RealToString( sel ), RealToString( sel + g - 1 ), RealToString( g ) );
                    ImGui::Separator();
                    TextFocused( "Max frame time:", TimeToString( f ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%.1f FPS)", 1000000000.0 / f );

                    if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { m_worker.GetFrameTime( *m_frames, sel ), m_worker.GetFrameTime( *m_frames, sel + g - 1 ), true };
                }
                else
                {
                    const auto fnum = GetFrameNumber( *m_frames, sel );
                    m_frameHover = sel;
                    if( m_frames->name == 0 )
                    {
                        if( sel == 0 )
                        {
                            ImGui::TextUnformatted( "Tracy initialization" );
                            ImGui::Separator();
                            TextFocused( "Time:", TimeToString( m_worker.GetFrameTime( *m_frames, sel ) ) );
                        }
                        else if( !m_worker.IsOnDemand() )
                        {
                            TextDisabledUnformatted( "Frame:" );
                            ImGui::SameLine();
                            ImGui::TextUnformatted( RealToString( fnum ) );
                            ImGui::Separator();
                            const auto frameTime = m_worker.GetFrameTime( *m_frames, sel );
                            TextFocused( "Frame time:", TimeToString( frameTime ) );
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(%.1f FPS)", 1000000000.0 / frameTime );
                        }
                        else if( sel == 1 )
                        {
                            ImGui::TextUnformatted( "Missed frames" );
                            ImGui::Separator();
                            TextFocused( "Time:", TimeToString( m_worker.GetFrameTime( *m_frames, 1 ) ) );
                        }
                        else
                        {
                            TextDisabledUnformatted( "Frame:" );
                            ImGui::SameLine();
                            ImGui::TextUnformatted( RealToString( fnum ) );
                            ImGui::Separator();
                            const auto frameTime = m_worker.GetFrameTime( *m_frames, sel );
                            TextFocused( "Frame time:", TimeToString( frameTime ) );
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(%.1f FPS)", 1000000000.0 / frameTime );
                        }
                    }
                    else
                    {
                        ImGui::TextDisabled( "%s:", GetFrameSetName( *m_frames ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( RealToString( fnum ) );
                        ImGui::Separator();
                        const auto frameTime = m_worker.GetFrameTime( *m_frames, sel );
                        TextFocused( "Frame time:", TimeToString( frameTime ) );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%.1f FPS)", 1000000000.0 / frameTime );
                    }
                }
                TextFocused( "Time from start of program:", TimeToStringExact( m_worker.GetFrameBegin( *m_frames, sel ) ) );
                auto fi = m_worker.GetFrameImage( *m_frames, sel );
                if( fi )
                {
                    if( fi != m_frameTexturePtr )
                    {
                        if( !m_frameTexture ) m_frameTexture = MakeTexture();
                        UpdateTexture( m_frameTexture, m_worker.UnpackFrameImage( *fi ), fi->w, fi->h );
                        m_frameTexturePtr = fi;
                    }
                    ImGui::Separator();
                    if( fi->flip )
                    {
                        ImGui::Image( m_frameTexture, ImVec2( fi->w * scale, fi->h * scale ), ImVec2( 0, 1 ), ImVec2( 1, 0 ) );
                    }
                    else
                    {
                        ImGui::Image( m_frameTexture, ImVec2( fi->w * scale, fi->h * scale ) );
                    }
                }
                ImGui::EndTooltip();

                if( io.KeyCtrl )
                {
                    if( fi && IsMouseDown( 0 ) )
                    {
                        m_showPlayback = true;
                        m_playback.pause = true;
                        SetPlaybackFrame( m_frames->frames[sel].frameImage );
                    }
                }
                else
                {
                    if( IsMouseClicked( 0 ) )
                    {
                        m_viewMode = ViewMode::Paused;
                        m_viewModeHeuristicTry = false;
                        m_zoomAnim.active = false;
                        if( !m_playback.pause && m_playback.sync ) m_playback.pause = true;
                        m_vd.zvStart = m_worker.GetFrameBegin( *m_frames, sel );
                        m_vd.zvEnd = m_worker.GetFrameEnd( *m_frames, sel + group - 1 );
                        if( m_vd.zvStart == m_vd.zvEnd ) m_vd.zvStart--;
                    }
                    else if( IsMouseDragging( 0 ) )
                    {
                        const auto t0 = std::min( m_vd.zvStart, m_worker.GetFrameBegin( *m_frames, sel ) );
                        const auto t1 = std::max( m_vd.zvEnd, m_worker.GetFrameEnd( *m_frames, sel + group - 1 ) );
                        ZoomToRange( t0, t1 );
                    }
                }

                if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { m_worker.GetFrameBegin( *m_frames, sel ), m_worker.GetFrameEnd( *m_frames, sel + group - 1 ), true };
            }

            if( ( !m_worker.IsConnected() || m_viewMode == ViewMode::Paused ) && wheel != 0 )
            {
                const int pfwidth = GetFrameWidth( prevScale );
                const int pgroup = GetFrameGroup( prevScale );

                const auto oldoff = mo * pgroup / pfwidth;
                m_vd.frameStart = std::min( total, std::max( 0, m_vd.frameStart - int( off - oldoff ) ) );
            }
        }
    }

    int i = 0, idx = 0;
#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreSourceLocationZonesReady() && m_findZone.show && m_findZone.showZoneInFrames && !m_findZone.match.empty() )
    {
        auto& zoneData = m_worker.GetZonesForSourceLocation( m_findZone.match[m_findZone.selMatch] );
        zoneData.zones.ensure_sorted();
        auto begin = zoneData.zones.begin();
        while( i < onScreen && m_vd.frameStart + idx < total )
        {
            const auto f0 = m_worker.GetFrameBegin( *m_frames, m_vd.frameStart + idx );
            auto f1 = m_worker.GetFrameEnd( *m_frames, m_vd.frameStart + idx );
            auto f = f1 - f0;
            if( group > 1 )
            {
                const int g = std::min( group, total - ( m_vd.frameStart + idx ) );
                for( int j=1; j<g; j++ )
                {
                    f = std::max( f, m_worker.GetFrameTime( *m_frames, m_vd.frameStart + idx + j ) );
                }
                f1 = m_worker.GetFrameEnd( *m_frames, m_vd.frameStart + idx + g - 1 );
            }

            int64_t zoneTime = 0;
            // This search is not valid, as zones are sorted according to their start time, not end time.
            auto itStart = std::lower_bound( begin, zoneData.zones.end(), f0, [] ( const auto& l, const auto& r ) { return l.Zone()->End() < r; } );
            if( itStart != zoneData.zones.end() )
            {
                auto itEnd = std::lower_bound( itStart, zoneData.zones.end(), f1, [] ( const auto& l, const auto& r ) { return l.Zone()->Start() < r; } );
                if( m_frames->continuous )
                {
                    if( m_findZone.selfTime )
                    {
                        while( itStart != itEnd )
                        {
                            const auto t0 = clamp( itStart->Zone()->Start(), f0, f1 );
                            const auto t1 = clamp( m_worker.GetZoneEndDirect( *itStart->Zone() ), f0, f1 );
                            zoneTime += t1 - t0 - GetZoneChildTimeFastClamped( *itStart->Zone(), t0, t1 );
                            itStart++;
                        }
                    }
                    else
                    {
                        while( itStart != itEnd )
                        {
                            const auto t0 = clamp( itStart->Zone()->Start(), f0, f1 );
                            const auto t1 = clamp( m_worker.GetZoneEndDirect( *itStart->Zone() ), f0, f1 );
                            zoneTime += t1 - t0;
                            itStart++;
                        }
                    }
                }
                else
                {
                    if( m_findZone.selfTime )
                    {
                        while( itStart != itEnd )
                        {
                            const int g = std::min( group, total - ( m_vd.frameStart + idx ) );
                            for( int j=0; j<g; j++ )
                            {
                                const auto ft0 = m_worker.GetFrameBegin( *m_frames, m_vd.frameStart + idx + j );
                                const auto ft1 = m_worker.GetFrameEnd( *m_frames, m_vd.frameStart + idx + j );
                                const auto t0 = clamp( itStart->Zone()->Start(), ft0, ft1 );
                                const auto t1 = clamp( m_worker.GetZoneEndDirect( *itStart->Zone() ), ft0, ft1 );
                                zoneTime += t1 - t0 - GetZoneChildTimeFastClamped( *itStart->Zone(), t0, t1 );
                            }
                            itStart++;
                        }
                    }
                    else
                    {
                        while( itStart != itEnd )
                        {
                            const int g = std::min( group, total - ( m_vd.frameStart + idx ) );
                            for( int j=0; j<g; j++ )
                            {
                                const auto ft0 = m_worker.GetFrameBegin( *m_frames, m_vd.frameStart + idx + j );
                                const auto ft1 = m_worker.GetFrameEnd( *m_frames, m_vd.frameStart + idx + j );
                                const auto t0 = clamp( itStart->Zone()->Start(), ft0, ft1 );
                                const auto t1 = clamp( m_worker.GetZoneEndDirect( *itStart->Zone() ), ft0, ft1 );
                                zoneTime += t1 - t0;
                            }
                            itStart++;
                        }
                    }
                }
            }
            else
            {
                begin = itStart;
            }

            zoneTime /= group;
            const auto h = std::max( 1.f, float( std::min<uint64_t>( MaxFrameTime, f ) ) / MaxFrameTime * ( Height - 2 ) );
            if( zoneTime == 0 )
            {
                if( fwidth != 1 )
                {
                    draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), 0xFF888888 );
                }
                else
                {
                    DrawLine( draw, dpos + ImVec2( 1+i, Height-2-h ), dpos + ImVec2( 1+i, Height-2 ), 0xFF888888 );
                }
            }
            else if( zoneTime <= f )
            {
                const auto zh = float( std::min<uint64_t>( MaxFrameTime, zoneTime ) ) / MaxFrameTime * ( Height - 2 );
                if( fwidth != 1 )
                {
                    draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1-zh ), 0xFF888888 );
                    draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-zh ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), 0xFFEEEEEE );
                }
                else
                {
                    DrawLine( draw, dpos + ImVec2( 1+i, Height-2-h ), dpos + ImVec2( 1+i, Height-2-zh ), 0xFF888888 );
                    DrawLine( draw, dpos + ImVec2( 1+i, Height-2-zh ), dpos + ImVec2( 1+i, Height-2 ), 0xFFEEEEEE );
                }
            }
            else
            {
                const auto zh = float( std::min<uint64_t>( MaxFrameTime, zoneTime ) ) / MaxFrameTime * ( Height - 2 );
                if( fwidth != 1 )
                {
                    draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-zh ), wpos + ImVec2( fwidth + i*fwidth, Height-1-h ), 0xFF2222BB );
                    draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), 0xFFEEEEEE );
                }
                else
                {
                    DrawLine( draw, dpos + ImVec2( 1+i, Height-2-zh ), dpos + ImVec2( 1+i, Height-2-h ), 0xFF2222BB );
                    DrawLine( draw, dpos + ImVec2( 1+i, Height-2-h ), dpos + ImVec2( 1+i, Height-2 ), 0xFFEEEEEE );
                }
            }

            i++;
            idx += group;
        }
    }
    else
#endif
    {
        while( i < onScreen && m_vd.frameStart + idx < total )
        {
            auto f = m_worker.GetFrameTime( *m_frames, m_vd.frameStart + idx );
            if( group > 1 )
            {
                const int g = std::min( group, total - ( m_vd.frameStart + idx ) );
                for( int j=1; j<g; j++ )
                {
                    f = std::max( f, m_worker.GetFrameTime( *m_frames, m_vd.frameStart + idx + j ) );
                }
            }

            const auto h = std::max( 1.f, float( std::min<uint64_t>( MaxFrameTime, f ) ) / MaxFrameTime * ( Height - 2 ) );
            if( fwidth != 1 )
            {
                draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), GetFrameColor( f, frameTarget ) );
            }
            else
            {
                DrawLine( draw, dpos + ImVec2( 1+i, Height-2-h ), dpos + ImVec2( 1+i, Height-2 ), GetFrameColor( f, frameTarget ) );
            }

            i++;
            idx += group;
        }
    }

    const auto zrange = m_worker.GetFrameRange( *m_frames, m_vd.zvStart, m_vd.zvEnd );
    if( zrange.second > m_vd.frameStart && zrange.first < m_vd.frameStart + onScreen * group )
    {
        auto x1 = std::min( onScreen * fwidth, ( zrange.second - m_vd.frameStart ) * fwidth / group );
        auto x0 = std::max( 0, ( zrange.first - m_vd.frameStart ) * fwidth / group );

        if( x0 == x1 ) x1 = x0 + 1;
        if( x1 - x0 >= 3 )
        {
            draw->AddRectFilled( wpos + ImVec2( 2+x0, 0 ), wpos + ImVec2( x1, Height ), 0x55DD22DD );
            DrawLine( draw, dpos + ImVec2( 1+x0, -1 ), dpos + ImVec2( 1+x0, Height-1 ), 0x55FF55FF );
            DrawLine( draw, dpos + ImVec2( x1, -1 ), dpos + ImVec2( x1, Height-1 ), 0x55FF55FF );
        }
        else
        {
            draw->AddRectFilled( wpos + ImVec2( 1+x0, 0 ), wpos + ImVec2( 1+x1, Height ), 0x55FF55FF );
        }
    }

    if( frameTarget * 2 <= MaxFrameTime ) DrawLine( draw, dpos + ImVec2( 0, round( Height - Height * frameTarget * 2 / MaxFrameTime ) ), dpos + ImVec2( w, round( Height - Height * frameTarget * 2 / MaxFrameTime ) ), 0x442222DD );
    if( frameTarget     <= MaxFrameTime ) DrawLine( draw, dpos + ImVec2( 0, round( Height - Height * frameTarget     / MaxFrameTime ) ), dpos + ImVec2( w, round( Height - Height * frameTarget     / MaxFrameTime ) ), 0x4422DDDD );
    if( frameTarget / 2 <= MaxFrameTime ) DrawLine( draw, dpos + ImVec2( 0, round( Height - Height * frameTarget / 2 / MaxFrameTime ) ), dpos + ImVec2( w, round( Height - Height * frameTarget / 2 / MaxFrameTime ) ), 0x4422DD22 );
}

}
