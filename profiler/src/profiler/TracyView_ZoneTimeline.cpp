#include <inttypes.h>

#include "TracyColor.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineDraw.hpp"
#include "TracyView.hpp"

namespace tracy
{

extern double s_time;

constexpr float MinVisSize = 3;

static tracy_force_inline uint32_t MixGhostColor( uint32_t c0, uint32_t c1 )
{
    return 0xFF000000 |
        ( ( ( ( ( c0 & 0x00FF0000 ) >> 16 ) + 3 * ( ( c1 & 0x00FF0000 ) >> 16 ) ) >> 2 ) << 16 ) |
        ( ( ( ( ( c0 & 0x0000FF00 ) >> 8  ) + 3 * ( ( c1 & 0x0000FF00 ) >> 8  ) ) >> 2 ) << 8  ) |
        ( ( ( ( ( c0 & 0x000000FF )       ) + 3 * ( ( c1 & 0x000000FF )       ) ) >> 2 )       );
}

void View::DrawThread( const TimelineContext& ctx, const ThreadData& thread, const std::vector<TimelineDraw>& draw, const std::vector<ContextSwitchDraw>& ctxDraw, const std::vector<SamplesDraw>& samplesDraw, const std::vector<std::unique_ptr<LockDraw>>& lockDraw, int& offset, int depth, bool _hasCtxSwitches, bool _hasSamples )
{
    const auto& wpos = ctx.wpos;
    const auto ty = ctx.ty;
    const auto ostep = ty + 1;
    const auto yMin = ctx.yMin;
    const auto yMax = ctx.yMax;
    const auto sty = ctx.sty;
    const auto sstep = sty + 1;

    const auto sampleOffset = offset;
    const auto hasSamples = m_vd.drawSamples && _hasSamples;
    const auto hasCtxSwitch = m_vd.drawContextSwitches && _hasCtxSwitches;

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
    if( hasCtxSwitch )
    {
        offset += round( ostep * 0.75f );
    }

    const auto yPos = wpos.y + offset;
    if( !draw.empty() && yPos <= yMax && yPos + ostep * depth >= yMin )
    {
        DrawZoneList( ctx, draw, offset, thread.id );
    }
    offset += ostep * depth;

    if( hasCtxSwitch && !ctxDraw.empty() )
    {
        auto ctxSwitch = m_worker.GetContextSwitchData( thread.id );
        assert( ctxSwitch );
        DrawContextSwitchList( ctx, ctxDraw, ctxSwitch->v, ctxOffset, offset, thread.isFiber );
    }
    if( hasSamples && !samplesDraw.empty() )
    {
        DrawSampleList( ctx, samplesDraw, thread.samples, sampleOffset );
    }

    if( m_vd.drawLocks )
    {
        const auto lockDepth = DrawLocks( ctx, lockDraw, thread.id, offset, m_nextLockHighlight );
        offset += sstep * lockDepth;
    }
}

void View::DrawThreadMessagesList( const TimelineContext& ctx, const std::vector<MessagesDraw>& drawList, int offset, uint64_t tid )
{
    const auto vStart = ctx.vStart;
    const auto vEnd = ctx.vEnd;
    const auto pxns = ctx.pxns;
    const auto hover = ctx.hover;
    const auto& wpos = ctx.wpos;
    const auto ty = ctx.ty;
    const auto to = 9.f * GetScale();
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;

    auto draw = ImGui::GetWindowDrawList();

    for( auto& v : drawList )
    {
        const auto& msg = *v.msg;
        const auto px = ( msg.time - vStart ) * pxns;
        const bool isMsgHovered = hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, offset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, offset + ty ) );

        unsigned int color = 0xFFDDDDDD;
        float animOff = 0;
        if( v.highlight )
        {
            color = 0xFF4444FF;
            if( !isMsgHovered )
            {
                animOff = -fabs( sin( s_time * 8 ) ) * th;
                m_wasActive = true;
            }
        }

        if( v.num == 1 )
        {
            draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, animOff + offset + to ), wpos + ImVec2( px + (ty - to) * 0.5, animOff + offset + to ), wpos + ImVec2( px, animOff + offset + to + th ), color, 2.0f );
        }
        else
        {
            draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.5, animOff + offset + to ), wpos + ImVec2( px + (ty - to) * 0.5, animOff + offset + to ), wpos + ImVec2( px, animOff + offset + to + th ), color );
            draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, animOff + offset + to ), wpos + ImVec2( px + (ty - to) * 0.5, animOff + offset + to ), wpos + ImVec2( px, animOff + offset + to + th ), color, 2.0f );
        }

        if( isMsgHovered )
        {
            ImGui::BeginTooltip();
            if( v.num > 1 )
            {
                ImGui::Text( "%" PRIu32 " messages", v.num );
            }
            else
            {
                TextFocused( "Message at", TimeToStringExact( msg.time ) );
                ImGui::PushStyleColor( ImGuiCol_Text, msg.color );
                ImGui::TextUnformatted( m_worker.GetString( msg.ref ) );
                ImGui::PopStyleColor();
            }
            ImGui::EndTooltip();
            m_msgHighlight = &msg;

            if( IsMouseClicked( 0 ) )
            {
                m_showMessages = true;
                m_msgToFocus = &msg;
            }
            if( IsMouseClicked( 2 ) )
            {
                CenterAtTime( msg.time );
            }
        }
    }

    auto& crash = m_worker.GetCrashEvent();
    if( crash.thread == tid && crash.time >= vStart && crash.time <= vEnd )
    {
        const auto px = ( crash.time - vStart ) * pxns;

        draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.25f, offset + to + th * 0.5f ), wpos + ImVec2( px + (ty - to) * 0.25f, offset + to + th * 0.5f ), wpos + ImVec2( px, offset + to + th ), 0xFF2222FF );
        draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.25f, offset + to + th * 0.5f ), wpos + ImVec2( px + (ty - to) * 0.25f, offset + to + th * 0.5f ), wpos + ImVec2( px, offset + to + th ), 0xFF2222FF, 2.0f );

        const auto crashText = ICON_FA_SKULL " crash " ICON_FA_SKULL;
        auto ctw = ImGui::CalcTextSize( crashText ).x;
        DrawTextContrast( draw, wpos + ImVec2( px - ctw * 0.5f, offset + to + th * 0.5f - ty ), 0xFF2222FF, crashText );

        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, offset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, offset + ty ) ) )
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

void View::DrawThreadOverlays( const ThreadData& thread, const ImVec2& ul, const ImVec2& dr )
{
    auto draw = ImGui::GetWindowDrawList();

    if( m_gpuThread == thread.id )
    {
        draw->AddRectFilled( ul, dr, 0x228888DD );
        draw->AddRect( ul, dr, 0x448888DD );
    }
    if( m_gpuInfoWindow && m_gpuInfoWindowThread == thread.id )
    {
        draw->AddRectFilled( ul, dr, 0x2288DD88 );
        draw->AddRect( ul, dr, 0x4488DD88 );
    }
    if( m_cpuDataThread == thread.id )
    {
        draw->AddRectFilled( ul, dr, 0x2DFF8888 );
        draw->AddRect( ul, dr, 0x4DFF8888 );
    }
}

void View::DrawZoneList( const TimelineContext& ctx, const std::vector<TimelineDraw>& drawList, int _offset, uint64_t tid )
{
    auto draw = ImGui::GetWindowDrawList();
    const auto w = ctx.w;
    const auto& wpos = ctx.wpos;
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto ty = ctx.ty;
    const auto ostep = ty + 1;
    const auto yMin = ctx.yMin;
    const auto yMax = ctx.yMax;
    const auto pxns = ctx.pxns;
    const auto hover = ctx.hover;
    const auto vStart = ctx.vStart;

    for( auto& v : drawList )
    {
        const auto offset = _offset + ostep * v.depth;
        const auto yPos = wpos.y + offset;
        if( yPos > yMax || yPos + ostep < yMin ) continue;

        switch( v.type )
        {
        case TimelineDrawType::Folded:
        {
            auto& ev = *(const ZoneEvent*)v.ev.get();
            const auto color = m_vd.dynamicColors == 2 ? 0xFF666666 : GetThreadColor( tid, v.depth );
            const auto rend = v.rend.Val();
            const auto px0 = ( ev.Start() - vStart ) * pxns;
            const auto px1 = ( rend - vStart ) * pxns;
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ), color );
            DrawZigZag( draw, wpos + ImVec2( 0, offset + ty/2 ), std::max( px0, -10.0 ), std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), ty/4, DarkenColor( color ) );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty + 1 ) ) )
            {
                if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { ev.Start(), rend, true };
                if( v.num > 1 )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Zones too small to display:", RealToString( v.num ) );
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( rend - ev.Start() ) );
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 2 ) && rend - ev.Start() > 0 )
                    {
                        ZoomToRange( ev.Start(), rend );
                    }
                }
                else
                {
                    ZoneTooltip( ev );

                    if( IsMouseClicked( 2 ) && rend - ev.Start() > 0 )
                    {
                        ZoomToZone( ev );
                    }
                    if( IsMouseClicked( 0 ) )
                    {
                        if( ImGui::GetIO().KeyCtrl )
                        {
                            auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
                            m_findZone.ShowZone( ev.SrcLoc(), m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ) );
                        }
                        else
                        {
                            ShowZoneInfo( ev );
                        }
                    }

                    m_zoneSrcLocHighlight = ev.SrcLoc();
                    m_zoneHover = &ev;
                }
            }
            const auto tmp = RealToString( v.num );
            const auto tsz = ImGui::CalcTextSize( tmp );
            if( tsz.x < px1 - px0 )
            {
                const auto x = px0 + ( px1 - px0 - tsz.x ) / 2;
                DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
            }
            break;
        }
        case TimelineDrawType::Zone:
        {
            auto& ev = *(const ZoneEvent*)v.ev.get();
            const auto end = m_worker.GetZoneEnd( ev );
            const auto zsz = std::max( ( end - ev.Start() ) * pxns, pxns * 0.5 );
            const auto zoneColor = GetZoneColorData( ev, tid, v.depth );
            const char* zoneName = m_worker.GetZoneName( ev );

            auto tsz = ImGui::CalcTextSize( zoneName );
            if( m_vd.shortenName == ShortenName::Always || ( ( m_vd.shortenName == ShortenName::NoSpace || m_vd.shortenName == ShortenName::NoSpaceAndNormalize ) && tsz.x > zsz ) )
            {
                zoneName = ShortenZoneName( m_vd.shortenName, zoneName, tsz, zsz );
            }

            const auto pr0 = ( ev.Start() - m_vd.zvStart ) * pxns;
            const auto pr1 = ( end - m_vd.zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );
            draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), zoneColor.color );
            if( zoneColor.highlight )
            {
                if( zoneColor.thickness > 1.f )
                {
                    draw->AddRect( wpos + ImVec2( px0 + 1, offset + 1 ), wpos + ImVec2( px1 - 1, offset + tsz.y - 1 ), zoneColor.accentColor, 0.f, -1, zoneColor.thickness );
                }
                else
                {
                    draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), zoneColor.accentColor, 0.f, -1, zoneColor.thickness );
                }
            }
            else
            {
                const auto darkColor = DarkenColor( zoneColor.color );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px0, offset ), dpos + ImVec2( px1-1, offset ), zoneColor.accentColor, zoneColor.thickness );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px1-1, offset + tsz.y ), dpos + ImVec2( px1-1, offset ), darkColor, zoneColor.thickness );
            }
            if( tsz.x < zsz )
            {
                const auto x = ( ev.Start() - m_vd.zvStart ) * pxns + ( ( end - ev.Start() ) * pxns - tsz.x ) / 2;
                if( x < 0 || x > w - tsz.x )
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, zoneName );
                    ImGui::PopClipRect();
                }
                else if( ev.Start() == ev.End() )
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
                DrawTextContrast( draw, wpos + ImVec2( std::max( int64_t( 0 ), ev.Start() - m_vd.zvStart ) * pxns, offset ), 0xFFFFFFFF, zoneName );
                ImGui::PopClipRect();
            }

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y + 1 ) ) )
            {
                ZoneTooltip( ev );
                if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { ev.Start(), m_worker.GetZoneEnd( ev ), true };

                if( !m_zoomAnim.active && IsMouseClicked( 2 ) )
                {
                    ZoomToZone( ev );
                }
                if( IsMouseClicked( 0 ) )
                {
                    if( ImGui::GetIO().KeyCtrl )
                    {
                        auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
                        m_findZone.ShowZone( ev.SrcLoc(), m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ) );
                    }
                    else
                    {
                        ShowZoneInfo( ev );
                    }
                }

                m_zoneSrcLocHighlight = ev.SrcLoc();
                m_zoneHover = &ev;
            }
            break;
        }
#ifndef TRACY_NO_STATISTICS
        case TimelineDrawType::GhostFolded:
        {
            auto& ev = *(const GhostZone*)v.ev.get();
            const auto color = m_vd.dynamicColors == 2 ? 0xFF666666 : MixGhostColor( GetThreadColor( tid, v.depth ), 0x665555 );
            const auto rend = v.rend.Val();
            const auto px0 = ( ev.start.Val() - m_vd.zvStart ) * pxns;
            const auto px1 = ( rend - m_vd.zvStart ) * pxns;
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ), color );
            DrawZigZag( draw, wpos + ImVec2( 0, offset + ty/2 ), std::max( px0, -10.0 ), std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), ty/4, DarkenColor( color ) );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty + 1 ) ) )
            {
                if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { ev.start.Val(), rend , true };
                ImGui::BeginTooltip();
                ImGui::TextUnformatted( "Multiple ghost zones" );
                ImGui::Separator();
                TextFocused( "Execution time:", TimeToString( rend - ev.start.Val() ) );
                ImGui::EndTooltip();

                if( IsMouseClicked( 2 ) && rend - ev.start.Val() > 0 )
                {
                    ZoomToRange( ev.start.Val(), rend );
                }
            }
            break;
        }
        case TimelineDrawType::Ghost:
        {
            auto& ev = *(const GhostZone*)v.ev.get();
            const auto end = ev.end.Val();
            const auto zsz = std::max( ( end - ev.start.Val() ) * pxns, pxns * 0.5 );

            const auto& ghostKey = m_worker.GetGhostFrame( ev.frame );
            const auto frame = m_worker.GetCallstackFrame( ghostKey.frame );

            uint32_t color;
            if( m_vd.dynamicColors == 2 )
            {
                if( frame )
                {
                    const auto& sym = frame->data[ghostKey.inlineFrame];
                    color = GetHsvColor( sym.name.Idx(), v.depth );
                }
                else
                {
                    color = GetHsvColor( ghostKey.frame.data, v.depth );
                }
            }
            else
            {
                color = MixGhostColor( GetThreadColor( tid, v.depth ), 0x665555 );
            }

            const auto pr0 = ( ev.start.Val() - m_vd.zvStart ) * pxns;
            const auto pr1 = ( ev.end.Val() - m_vd.zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );
            if( !frame )
            {
                char symName[64];
                sprintf( symName, "0x%" PRIx64, m_worker.GetCanonicalPointer( ghostKey.frame ) );
                const auto tsz = ImGui::CalcTextSize( symName );

                const auto accentColor = HighlightColor( color );
                const auto darkColor = DarkenColor( color );
                const auto txtColor = 0xFF888888;
                draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), DarkenColor( color ) );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px0, offset ), dpos + ImVec2( px1-1, offset ), accentColor, 1.f );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px1-1, offset + tsz.y ), dpos + ImVec2( px1-1, offset ), darkColor, 1.f );

                if( tsz.x < zsz )
                {
                    const auto x = ( ev.start.Val() - m_vd.zvStart ) * pxns + ( ( end - ev.start.Val() ) * pxns - tsz.x ) / 2;
                    if( x < 0 || x > w - tsz.x )
                    {
                        ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                        DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), txtColor, symName );
                        ImGui::PopClipRect();
                    }
                    else if( ev.start.Val() == ev.end.Val() )
                    {
                        DrawTextContrast( draw, wpos + ImVec2( px0 + ( px1 - px0 - tsz.x ) * 0.5, offset ), txtColor, symName );
                    }
                    else
                    {
                        DrawTextContrast( draw, wpos + ImVec2( x, offset ), txtColor, symName );
                    }
                }
                else
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( ( ev.start.Val() - m_vd.zvStart ) * pxns, offset ), txtColor, symName );
                    ImGui::PopClipRect();
                }

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y + 1 ) ) )
                {
                    if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { ev.start.Val(), ev.end.Val() , true };
                    ImGui::BeginTooltip();
                    TextDisabledUnformatted( ICON_FA_GHOST " Ghost zone" );
                    ImGui::Separator();
                    TextFocused( "Unknown frame:", symName );
                    TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( tid ) );
                    if( m_worker.IsThreadFiber( tid ) )
                    {
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
                    }
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( ev.end.Val() - ev.start.Val() ) );
                    ImGui::EndTooltip();
                    if( !m_zoomAnim.active && IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( ev.start.Val(), ev.end.Val() );
                    }
                }
            }
            else
            {
                const auto& sym = frame->data[ghostKey.inlineFrame];
                const auto isInline = ghostKey.inlineFrame != frame->size-1;
                const auto col = isInline ? DarkenColor( color ) : color;
                auto symName = m_worker.GetString( sym.name );
                uint32_t txtColor;
                if( symName[0] == '[' )
                {
                    txtColor = 0xFF999999;
                }
                else if( !isInline && ( m_worker.GetCanonicalPointer( ghostKey.frame ) >> 63 != 0 ) )
                {
                    txtColor = 0xFF8888FF;
                }
                else
                {
                    txtColor = 0xFFFFFFFF;
                }
                auto tsz = ImGui::CalcTextSize( symName );

                const auto accentColor = HighlightColor( col );
                const auto darkColor = DarkenColor( col );
                draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), col );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px0, offset ), dpos + ImVec2( px1-1, offset ), accentColor, 1.f );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px1-1, offset + tsz.y ), dpos + ImVec2( px1-1, offset ), darkColor, 1.f );

                auto origSymName = symName;
                if( m_vd.shortenName != ShortenName::Never && ( m_vd.shortenName != ShortenName::NoSpace || tsz.x > zsz ) )
                {
                    symName = ShortenZoneName( m_vd.shortenName, symName, tsz, zsz );
                }

                if( tsz.x < zsz )
                {
                    const auto x = ( ev.start.Val() - m_vd.zvStart ) * pxns + ( ( end - ev.start.Val() ) * pxns - tsz.x ) / 2;
                    if( x < 0 || x > w - tsz.x )
                    {
                        ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                        DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), txtColor, symName );
                        ImGui::PopClipRect();
                    }
                    else if( ev.start.Val() == ev.end.Val() )
                    {
                        DrawTextContrast( draw, wpos + ImVec2( px0 + ( px1 - px0 - tsz.x ) * 0.5, offset ), txtColor, symName );
                    }
                    else
                    {
                        DrawTextContrast( draw, wpos + ImVec2( x, offset ), txtColor, symName );
                    }
                }
                else
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( std::max( int64_t( 0 ), ev.start.Val() - m_vd.zvStart ) * pxns, offset ), txtColor, symName );
                    ImGui::PopClipRect();
                }

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y + 1 ) ) )
                {
                    if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { ev.start.Val(), ev.end.Val(), true };
                    ImGui::BeginTooltip();
                    TextDisabledUnformatted( ICON_FA_GHOST " Ghost zone" );
                    if( sym.symAddr >> 63 != 0 )
                    {
                        ImGui::SameLine();
                        TextDisabledUnformatted( ICON_FA_HAT_WIZARD " kernel" );
                    }
                    ImGui::Separator();
                    const auto normalized = m_vd.shortenName == ShortenName::Never ? origSymName : ShortenZoneName( ShortenName::OnlyNormalize, origSymName );
                    ImGui::TextUnformatted( normalized );
                    if( isInline )
                    {
                        ImGui::SameLine();
                        TextDisabledUnformatted( "[inline]" );
                    }
                    if( normalized != origSymName && strcmp( normalized, origSymName ) != 0 )
                    {
                        ImGui::PushFont( m_smallFont );
                        TextDisabledUnformatted( origSymName );
                        ImGui::PopFont();
                    }
                    const auto symbol = m_worker.GetSymbolData( sym.symAddr );
                    if( symbol ) TextFocused( "Image:", m_worker.GetString( symbol->imageName ) );
                    TextDisabledUnformatted( "Location:" );
                    ImGui::SameLine();
                    const char* file = m_worker.GetString( sym.file );
                    uint32_t line = sym.line;
                    ImGui::TextUnformatted( LocationToString( file, line ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(0x%" PRIx64 ")", sym.symAddr );
                    TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( tid ) );
                    if( m_worker.IsThreadFiber( tid ) )
                    {
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
                    }
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( ev.end.Val() - ev.start.Val() ) );
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 0 ) )
                    {
                        ViewDispatch( file, line, sym.symAddr );
                    }
                    else if( !m_zoomAnim.active && IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( ev.start.Val(), ev.end.Val() );
                    }
                }
            }
            break;
        }
#endif
        default:
            assert( false );
            break;
        }
    }
}

}
