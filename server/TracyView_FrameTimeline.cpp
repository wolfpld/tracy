#include <algorithm>
#include <math.h>

#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTexture.hpp"
#include "TracyView.hpp"

namespace tracy
{

constexpr float MinVisSize = 3;
constexpr float MinFrameSize = 5;

static tracy_force_inline uint32_t GetColorMuted( uint32_t color, bool active )
{
    if( active )
    {
        return 0xFF000000 | color;
    }
    else
    {
        return 0x66000000 | color;
    }
}

void View::DrawTimelineFramesHeader()
{
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto w = ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ScrollbarSize;
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetTextLineHeight();
    const auto ty025 = round( ty * 0.25f );
    const auto ty0375 = round( ty * 0.375f );
    const auto ty05 = round( ty * 0.5f );

    const auto timespan = m_vd.zvEnd - m_vd.zvStart;
    const auto pxns = w / double( timespan );
    const auto nspx = 1.0 / pxns;
    const auto scale = std::max( 0.0, round( log10( nspx ) + 2 ) );
    const auto step = pow( 10, scale );

    ImGui::InvisibleButton( "##zoneFrames", ImVec2( w, ty * 1.5f ) );
    TooltipIfHovered( TimeToStringExact( m_vd.zvStart + ( ImGui::GetIO().MousePos.x - wpos.x ) * nspx ) );

    const auto dx = step * pxns;
    double x = 0;
    int tw = 0;
    int tx = 0;
    int64_t tt = 0;
    while( x < w )
    {
        DrawLine( draw, dpos + ImVec2( x, 0 ), dpos + ImVec2( x, ty05 ), 0x66FFFFFF );
        if( tw == 0 )
        {
            char buf[128];
            auto txt = TimeToStringExact( m_vd.zvStart );
            if( m_vd.zvStart >= 0 )
            {
                sprintf( buf, "+%s", txt );
                txt = buf;
            }
            draw->AddText( wpos + ImVec2( x, ty05 ), 0x66FFFFFF, txt );
            tw = ImGui::CalcTextSize( txt ).x;
        }
        else if( x > tx + tw + ty * 2 )
        {
            tx = x;
            auto txt = TimeToString( tt );
            draw->AddText( wpos + ImVec2( x, ty05 ), 0x66FFFFFF, txt );
            tw = ImGui::CalcTextSize( txt ).x;
        }

        if( scale != 0 )
        {
            for( int i=1; i<5; i++ )
            {
                DrawLine( draw, dpos + ImVec2( x + i * dx / 10, 0 ), dpos + ImVec2( x + i * dx / 10, ty025 ), 0x33FFFFFF );
            }
            DrawLine( draw, dpos + ImVec2( x + 5 * dx / 10, 0 ), dpos + ImVec2( x + 5 * dx / 10, ty0375 ), 0x33FFFFFF );
            for( int i=6; i<10; i++ )
            {
                DrawLine( draw, dpos + ImVec2( x + i * dx / 10, 0 ), dpos + ImVec2( x + i * dx / 10, ty025 ), 0x33FFFFFF );
            }
        }

        x += dx;
        tt += step;
    }
}

void View::DrawTimelineFrames( const FrameData& frames )
{
    const std::pair <int, int> zrange = m_worker.GetFrameRange( frames, m_vd.zvStart, m_vd.zvEnd );
    if( zrange.first < 0 ) return;
    if( m_worker.GetFrameBegin( frames, zrange.first ) > m_vd.zvEnd || m_worker.GetFrameEnd( frames, zrange.second ) < m_vd.zvStart ) return;

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto w = ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ScrollbarSize;
    const auto wh = ImGui::GetContentRegionAvail().y;
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetTextLineHeight();
    const auto ty025 = ty * 0.25f;
    const auto ty05 = round( ty * 0.5f );

    ImGui::InvisibleButton( "##zoneFrames", ImVec2( w, ty ) );
    bool hover = ImGui::IsItemHovered();

    auto timespan = m_vd.zvEnd - m_vd.zvStart;
    auto pxns = w / double( timespan );

    const auto nspx = 1.0 / pxns;

    int64_t prev = -1;
    int64_t prevEnd = -1;
    int64_t endPos = -1;
    bool tooltipDisplayed = false;
    const auto activeFrameSet = m_frames == &frames;
    const int64_t frameTarget = ( activeFrameSet && m_vd.drawFrameTargets ) ? 1000000000ll / m_vd.frameTarget : std::numeric_limits<int64_t>::max();

    const auto inactiveColor = GetColorMuted( 0x888888, activeFrameSet );
    const auto activeColor = GetColorMuted( 0xFFFFFF, activeFrameSet );
    const auto redColor = GetColorMuted( 0x4444FF, activeFrameSet );

    int i = zrange.first;
    auto x1 = ( m_worker.GetFrameBegin( frames, i ) - m_vd.zvStart ) * pxns;
    while( i < zrange.second )
    {
        const auto ftime = m_worker.GetFrameTime( frames, i );
        const auto fbegin = m_worker.GetFrameBegin( frames, i );
        const auto fend = m_worker.GetFrameEnd( frames, i );
        const auto fsz = pxns * ftime;

        if( hover )
        {
            const auto x0 = frames.continuous ? x1 : ( fbegin - m_vd.zvStart ) * pxns;
            x1 = ( fend - m_vd.zvStart ) * pxns;
            if( ImGui::IsMouseHoveringRect( wpos + ImVec2( x0, 0 ), wpos + ImVec2( x1, ty ) ) )
            {
                tooltipDisplayed = true;
                if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { fbegin, fend, true };

                ImGui::BeginTooltip();
                ImGui::TextUnformatted( GetFrameText( frames, i, ftime ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%.1f FPS)", 1000000000.0 / ftime );
                TextFocused( "Time from start of program:", TimeToStringExact( m_worker.GetFrameBegin( frames, i ) ) );
                auto fi = m_worker.GetFrameImage( frames, i );
                if( fi )
                {
                    const auto scale = GetScale();
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

                    if( ImGui::GetIO().KeyCtrl && IsMouseClicked( 0 ) )
                    {
                        m_showPlayback = true;
                        m_playback.pause = true;
                        SetPlaybackFrame( frames.frames[i].frameImage );
                    }
                }
                ImGui::EndTooltip();

                if( IsMouseClicked( 2 ) )
                {
                    ZoomToRange( fbegin, fend );
                }

                if( activeFrameSet ) m_frameHover = i;
            }
        }

        if( fsz < MinFrameSize )
        {
            if( !frames.continuous && prev != -1 )
            {
                if( ( fbegin - prevEnd ) * pxns >= MinFrameSize )
                {
                    DrawZigZag( draw, wpos + ImVec2( 0, ty05 ), ( prev - m_vd.zvStart ) * pxns, ( prevEnd - m_vd.zvStart ) * pxns, ty025, inactiveColor );
                    prev = -1;
                }
                else
                {
                    prevEnd = std::max<int64_t>( fend, fbegin + MinFrameSize * nspx );
                }
            }
            if( prev == -1 )
            {
                prev = fbegin;
                prevEnd = std::max<int64_t>( fend, fbegin + MinFrameSize * nspx );
            }

            const auto begin = frames.frames.begin() + i;
            const auto end = frames.frames.begin() + zrange.second;
            auto it = std::lower_bound( begin, end, int64_t( fbegin + MinVisSize * nspx ), [this, &frames] ( const auto& l, const auto& r ) { return m_worker.GetFrameEnd( frames, std::distance( frames.frames.begin(), &l ) ) < r; } );
            if( it == begin ) ++it;
            i += std::distance( begin, it );
            continue;
        }

        if( prev != -1 )
        {
            if( frames.continuous )
            {
                DrawZigZag( draw, wpos + ImVec2( 0, ty05 ), ( prev - m_vd.zvStart ) * pxns, ( fbegin - m_vd.zvStart ) * pxns, ty025, inactiveColor );
            }
            else
            {
                DrawZigZag( draw, wpos + ImVec2( 0, ty05 ), ( prev - m_vd.zvStart ) * pxns, ( prevEnd - m_vd.zvStart ) * pxns, ty025, inactiveColor );
            }
            prev = -1;
        }

        if( activeFrameSet )
        {
            if( fend - fbegin > frameTarget )
            {
                draw->AddRectFilled( wpos + ImVec2( ( fbegin + frameTarget - m_vd.zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_vd.zvStart ) * pxns, wh ), 0x224444FF );
            }
            if( fbegin >= m_vd.zvStart && endPos != fbegin )
            {
                DrawLine( draw, dpos + ImVec2( ( fbegin - m_vd.zvStart ) * pxns, 0 ), dpos + ImVec2( ( fbegin - m_vd.zvStart ) * pxns, wh ), 0x22FFFFFF );
            }
            if( fend <= m_vd.zvEnd )
            {
                DrawLine( draw, dpos + ImVec2( ( fend - m_vd.zvStart ) * pxns, 0 ), dpos + ImVec2( ( fend - m_vd.zvStart ) * pxns, wh ), 0x22FFFFFF );
            }
            endPos = fend;
        }

        auto buf = GetFrameText( frames, i, ftime );
        auto tx = ImGui::CalcTextSize( buf ).x;
        uint32_t color = ( frames.name == 0 && i == 0 ) ? redColor : activeColor;

        if( fsz - 7 <= tx )
        {
            static char tmp[256];
            sprintf( tmp, "%s (%s)", RealToString( i ), TimeToString( ftime ) );
            buf = tmp;
            tx = ImGui::CalcTextSize( buf ).x;
        }
        if( fsz - 7 <= tx )
        {
            buf = TimeToString( ftime );
            tx = ImGui::CalcTextSize( buf ).x;
        }

        if( fbegin >= m_vd.zvStart )
        {
            DrawLine( draw, dpos + ImVec2( ( fbegin - m_vd.zvStart ) * pxns + 2, 1 ), dpos + ImVec2( ( fbegin - m_vd.zvStart ) * pxns + 2, ty - 1 ), color );
        }
        if( fend <= m_vd.zvEnd )
        {
            DrawLine( draw, dpos + ImVec2( ( fend - m_vd.zvStart ) * pxns - 2, 1 ), dpos + ImVec2( ( fend - m_vd.zvStart ) * pxns - 2, ty - 1 ), color );
        }
        if( fsz - 7 > tx )
        {
            const auto f0 = ( fbegin - m_vd.zvStart ) * pxns + 2;
            const auto f1 = ( fend - m_vd.zvStart ) * pxns - 2;
            const auto x0 = f0 + 1;
            const auto x1 = f1 - 1;
            const auto te = x1 - tx;

            auto tpos = ( x0 + te ) / 2;
            if( tpos < 0 )
            {
                tpos = std::min( std::min( 0., te - tpos ), te );
            }
            else if( tpos > w - tx )
            {
                tpos = std::max( double( w - tx ), x0 );
            }
            tpos = round( tpos );

            DrawLine( draw, dpos + ImVec2( std::max( -10.0, f0 ), ty05 ), dpos + ImVec2( tpos, ty05 ), color );
            DrawLine( draw, dpos + ImVec2( std::max( -10.0, tpos + tx + 1 ), ty05 ), dpos + ImVec2( std::min( w + 20.0, f1 ), ty05 ), color );
            draw->AddText( wpos + ImVec2( tpos, 0 ), color, buf );
        }
        else
        {
            DrawLine( draw, dpos + ImVec2( std::max( -10.0, ( fbegin - m_vd.zvStart ) * pxns + 2 ), ty05 ), dpos + ImVec2( std::min( w + 20.0, ( fend - m_vd.zvStart ) * pxns - 2 ), ty05 ), color );
        }

        i++;
    }

    if( prev != -1 )
    {
        if( frames.continuous )
        {
            DrawZigZag( draw, wpos + ImVec2( 0, ty05 ), ( prev - m_vd.zvStart ) * pxns, ( m_worker.GetFrameBegin( frames, zrange.second-1 ) - m_vd.zvStart ) * pxns, ty025, inactiveColor );
        }
        else
        {
            const auto begin = ( prev - m_vd.zvStart ) * pxns;
            const auto end = ( m_worker.GetFrameBegin( frames, zrange.second-1 ) - m_vd.zvStart ) * pxns;
            DrawZigZag( draw, wpos + ImVec2( 0, ty05 ), begin, std::max( begin + MinFrameSize, end ), ty025, inactiveColor );
        }
    }

    if( hover )
    {
        if( !tooltipDisplayed )
        {
            ImGui::BeginTooltip();
            TextDisabledUnformatted( "Frame set:" );
            ImGui::SameLine();
            ImGui::TextUnformatted( GetFrameSetName( frames ) );
            ImGui::EndTooltip();
        }
        if( IsMouseClicked( 0 ) )
        {
            m_frames = &frames;
        }
    }
}

}
