#include <algorithm>
#include <math.h>

#include "TracyColor.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTexture.hpp"
#include "TracyView.hpp"

#include "tracy_pdqsort.h"

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

    ImGui::PushID( &frames );
    ImGui::InvisibleButton( "##zoneFrames", ImVec2( w, ty ) );
    ImGui::PopID();
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
                    ImGui::Separator();
                    DrawFrameImage( m_FrameTextureCache, *fi );

                    if( ImGui::GetIO().KeyCtrl && IsMouseClicked( 0 ) )
                    {
                        m_showPlayback = true;
                        m_playback.pause = true;
                        SetPlaybackFrame( frames.frames[i].frameImage, true );
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

struct SectionEntry
{
    uint32_t idx;
    int64_t len;
    int64_t start;
    int64_t end;
};

struct SectionRow
{
    std::vector<uint32_t> items;
    std::vector<std::pair<int64_t, int64_t>> available;
};

void View::DrawTimelineSections()
{
    auto& data = m_worker.GetSections();
    if( data.empty() ) return;

    uint32_t idx = 0;
    std::vector<SectionEntry> visible;
    visible.reserve( data.size() );
    for( auto& v : data )
    {
        const auto start = v.start.Val();
        const auto end = v.end.IsNonNegative() ? v.end.Val() : m_worker.GetLastTime();
        if( end - start > 0 && start < m_vd.zvEnd && end > m_vd.zvStart ) visible.emplace_back( SectionEntry {
            .idx = idx,
            .len = end - start,
            .start = std::max( start, m_vd.zvStart ),
            .end = std::min( end, m_vd.zvEnd )
        } );
        idx++;
    }
    if( visible.empty() ) return;

    pdqsort( visible.begin(), visible.end(), []( const SectionEntry& a, const SectionEntry& b ) { return a.len > b.len; } );

    std::vector<SectionRow> rows;
    for( auto& e : visible )
    {
        bool found = false;
        for( auto& row : rows )
        {
            for( size_t i=0; i<row.available.size(); i++ )
            {
                const auto gap = row.available[i];
                if( gap.first <= e.start && gap.second >= e.end )
                {
                    row.available.erase( row.available.begin() + i );
                    if( gap.second > e.end ) row.available.insert( row.available.begin() + i, { e.end, gap.second } );
                    if( gap.first < e.start ) row.available.insert( row.available.begin() + i, { gap.first, e.start } );
                    row.items.push_back( e.idx );
                    found = true;
                    break;
                }
            }
            if( found ) break;
        }
        if( !found )
        {
            rows.emplace_back();
            auto& row = rows.back();
            if( m_vd.zvStart < e.start ) row.available.emplace_back( m_vd.zvStart, e.start );
            if( m_vd.zvEnd > e.end ) row.available.emplace_back( e.end, m_vd.zvEnd );
            row.items.push_back( e.idx );
        }
    }

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto w = ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ScrollbarSize;
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;

    ImGui::InvisibleButton( "##sections", ImVec2( w, ostep * rows.size() ) );
    const bool hover = ImGui::IsItemHovered();

    const auto timespan = m_vd.zvEnd - m_vd.zvStart;
    const auto pxns = w / double( timespan );
    const auto nspx = 1.0 / pxns;
    const auto MinVisNs = int64_t( round( GetScale() * MinVisSize * nspx ) );

    int rowidx = 0;
    for( auto& row : rows )
    {
        const auto offset = ostep * rowidx;

        pdqsort_branchless( row.items.begin(), row.items.end(), [&data]( uint32_t a, uint32_t b ) { return data[a].start.Val() < data[b].start.Val(); } );

        size_t i = 0;
        while( i < row.items.size() )
        {
            auto& v = data[row.items[i]];
            const auto start = v.start.Val();
            const auto end = v.end.IsNonNegative() ? v.end.Val() : m_worker.GetLastTime();
            const auto zsz = end - start;

            if( zsz < MinVisNs )
            {
                uint32_t count = 1;
                auto groupEnd = end;
                size_t j = i + 1;
                while( j < row.items.size() )
                {
                    auto& nv = data[row.items[j]];
                    const auto nStart = nv.start.Val();
                    const auto nEnd = nv.end.IsNonNegative() ? nv.end.Val() : m_worker.GetLastTime();
                    if( ( nEnd - nStart ) >= MinVisNs ) break;
                    if( nStart > groupEnd + MinVisNs ) break;
                    groupEnd = nEnd;
                    ++count;
                    ++j;
                }

                const auto pr0 = ( start - m_vd.zvStart ) * pxns;
                const auto pr1 = ( groupEnd - m_vd.zvStart ) * pxns;
                const auto px0 = std::max( pr0, -10.0 );
                const auto px1 = std::min( std::max( pr1, px0 + MinVisSize ), double( w + 10 ) );
                constexpr uint32_t color = 0xFF666666;
                const auto darkColor = DarkenColor( color );

                draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + ty ), color );
                DrawZigZag( draw, wpos + ImVec2( 0, offset + ty/2 ), std::max( px0, -10.0 ), std::min( std::max( pr1, px0 + MinVisSize ), double( w + 10 ) ), ty/4, darkColor );

                const auto tmp = RealToString( count );
                const auto tsz = ImGui::CalcTextSize( tmp );
                const auto tpx0 = std::max( px0, 0.0 );
                if( tsz.x < px1 - tpx0 )
                {
                    const auto x = tpx0 + ( px1 - tpx0 - tsz.x ) / 2;
                    DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
                }

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( pr1, px0 + MinVisSize ), double( w + 10 ) ), offset + ty + 1 ) ) )
                {
                    ImGui::BeginTooltip();
                    if( count > 1 )
                    {
                        TextFocused( "Sections too small to display:", RealToString( count ) );
                        ImGui::Separator();
                        TextFocused( "Execution time:", TimeToString( groupEnd - start ) );
                        ImGui::EndTooltip();

                        if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { start, groupEnd, true };
                        if( IsMouseClicked( 2 ) ) ZoomToRange( start, groupEnd );
                    }
                    else
                    {
                        const char* name = m_worker.GetString( v.text );
                        ImGui::TextUnformatted( name );
                        ImGui::Separator();
                        TextFocused( "Execution time:", TimeToString( end - start ) );
                        TextFocused( "Time from start of program:", TimeToStringExact( start ) );
                        ImGui::EndTooltip();

                        if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { start, end, true };
                        if( IsMouseClicked( 2 ) ) ZoomToRange( start, end );
                    }
                }

                i = j;
            }
            else
            {
                const auto pr0 = ( start - m_vd.zvStart ) * pxns;
                const auto pr1 = ( end - m_vd.zvStart ) * pxns;
                const auto px0 = std::max( pr0, -10.0 );
                const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );

                const char* name = m_worker.GetString( v.text );
                const auto color = GetHsvColor( charutil::hash( name ), 0 );

                draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + ty ), color );
                const auto darkColor = DarkenColor( color );
                DrawLine( draw, dpos + ImVec2( px0, offset + ty ), dpos + ImVec2( px0, offset ), dpos + ImVec2( px1-1, offset ), HighlightColor( color ) );
                DrawLine( draw, dpos + ImVec2( px0, offset + ty ), dpos + ImVec2( px1-1, offset + ty ), dpos + ImVec2( px1-1, offset ), darkColor );

                const auto tsz = ImGui::CalcTextSize( name );
                const auto tpx0 = std::max( px0, 0.0 );
                if( tsz.x < px1 - tpx0 )
                {
                    const auto x = pr0 + ( pr1 - pr0 - tsz.x ) / 2;
                    if( x < 0 || x > w - tsz.x )
                    {
                        ImGui::PushClipRect( wpos + ImVec2( tpx0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                        DrawTextContrast( draw, wpos + ImVec2( std::max( tpx0, std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, name );
                        ImGui::PopClipRect();
                    }
                    else
                    {
                        DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFFFFFFFF, name );
                    }
                }
                else
                {
                    ImGui::PushClipRect( wpos + ImVec2( tpx0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( tpx0, offset ), 0xFFFFFFFF, name );
                    ImGui::PopClipRect();
                }

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + ty + 1 ) ) )
                {
                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted( name );
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( end - start ) );
                    TextFocused( "Time from start of program:", TimeToStringExact( start ) );
                    ImGui::EndTooltip();

                    if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { start, end, true };
                    if( IsMouseClicked( 2 ) ) ZoomToRange( start, end );
                }

                ++i;
            }
        }
        rowidx++;
    }
}

}
