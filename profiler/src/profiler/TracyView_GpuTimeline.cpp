#include "TracyColor.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyView.hpp"
#include "../Fonts.hpp"

namespace tracy
{

constexpr float MinVisSize = 3;

bool View::DrawGpu( const TimelineContext& ctx, const GpuCtxData& gpu, int& offset )
{
    const auto w = ctx.w;
    const auto ty = ctx.ty;
    const auto ostep = ty + 1;
    const auto pxns = ctx.pxns;
    const auto nspx = ctx.nspx;
    const auto& wpos = ctx.wpos;
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto hover = ctx.hover;
    const auto yMin = ctx.yMin;
    const auto yMax = ctx.yMax;

    auto draw = ImGui::GetWindowDrawList();

    ImGui::PushFont( g_fonts.normal, FontSmall );
    const auto sty = ImGui::GetTextLineHeight();
    const auto sstep = sty + 1;
    ImGui::PopFont();

    const auto singleThread = gpu.threadData.size() == 1;
    int depth = 0;

    for( auto& td : gpu.threadData )
    {
        auto& tl = td.second.timeline;
        assert( !tl.empty() );
        if( tl.is_magic() )
        {
            auto& tlm = *(Vector<ZoneEvent>*)&tl;
            if( tlm.front().Start() >= 0 )
            {
                const auto begin = tlm.front().Start();
                const auto drift = GpuDrift( &gpu );
                if( !singleThread ) offset += sstep;
                const auto partDepth = DispatchGpuZoneLevel( tl, hover, pxns, int64_t( nspx ), wpos, offset, 0, &gpu, yMin, yMax, begin, drift );
                if( partDepth != 0 )
                {
                    if( !singleThread )
                    {
                        ImGui::PushFont( g_fonts.normal, FontSmall );
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
            if( tl.front()->Start() >= 0 )
            {
                const auto begin = tl.front()->Start();
                const auto drift = GpuDrift( &gpu );
                if( !singleThread ) offset += sstep;
                const auto partDepth = DispatchGpuZoneLevel( tl, hover, pxns, int64_t( nspx ), wpos, offset, 0, &gpu, yMin, yMax, begin, drift );
                if( partDepth != 0 )
                {
                    if( !singleThread )
                    {
                        ImGui::PushFont( g_fonts.normal, FontSmall );
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
    return depth != 0;
}

int View::DispatchGpuZoneLevel( const Vector<short_ptr<ZoneEvent>>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, const GpuCtxData *ctx, float yMin, float yMax, int64_t begin, int drift )
{
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;

    const auto yPos = wpos.y + offset;
    if( yPos + ostep >= yMin && yPos <= yMax )
    {
        if( vec.is_magic() )
        {
            return DrawGpuZoneLevel<VectorAdapterDirect<ZoneEvent>>( *(Vector<ZoneEvent>*)&vec, hover, pxns, nspx, wpos, _offset, depth, ctx, yMin, yMax, begin, drift );
        }
        else
        {
            return DrawGpuZoneLevel<VectorAdapterPointer<ZoneEvent>>( vec, hover, pxns, nspx, wpos, _offset, depth, ctx, yMin, yMax, begin, drift );
        }
    }
    else
    {
        if( vec.is_magic() )
        {
            return SkipGpuZoneLevel<VectorAdapterDirect<ZoneEvent>>( *(Vector<ZoneEvent>*)&vec, hover, pxns, nspx, wpos, _offset, depth, ctx, yMin, yMax, begin, drift );
        }
        else
        {
            return SkipGpuZoneLevel<VectorAdapterPointer<ZoneEvent>>( vec, hover, pxns, nspx, wpos, _offset, depth, ctx, yMin, yMax, begin, drift );
        }
    }
}

template<typename Adapter, typename V>
int View::DrawGpuZoneLevel( const V& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, const GpuCtxData* ctx, float yMin, float yMax, int64_t begin, int drift )
{
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, m_vd.zvStart ), [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).End(), begin, drift ) < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    Adapter a;

    const auto zitend = std::lower_bound( it, vec.end(), std::max<int64_t>( 0, m_vd.zvEnd ), [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).Start(), begin, drift ) < (uint64_t)r; } );
    if( it == zitend ) return depth;
    if( AdjustGpuTime( a(*(zitend-1)).End(), begin, drift ) < m_vd.zvStart ) return depth;

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;
    auto draw = ImGui::GetWindowDrawList();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = m_worker.GetGpuExtra(a(*it));
        auto end = m_worker.GetZoneEndGPU( ev );
        if( end == std::numeric_limits<int64_t>::max() ) break;
        const auto start = AdjustGpuTime( ev.GpuStart(), begin, drift );
        end = AdjustGpuTime( end, begin, drift );
        const auto zsz = std::max( ( end - start ) * pxns, pxns * 0.5 );
        const auto zoneThread = ctx->thread != 0 ? ctx->thread : m_worker.DecompressThread( ev.Thread() );
        if( zsz < MinVisSize )
        {
            const auto color = GetZoneColor( { &ev.event, ctx }, zoneThread, depth );
            const auto MinVisNs = MinVisSize * nspx;
            int num = 0;
            const auto px0 = ( start - m_vd.zvStart ) * pxns;
            auto px1ns = end - m_vd.zvStart;
            auto rend = end;
            auto nextTime = end + MinVisNs;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, std::max<int64_t>( 0, nextTime ), [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).End(), begin, drift ) < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                num += std::distance( prevIt, it );
                if( it == zitend ) break;
                const auto nend = AdjustGpuTime( m_worker.GetZoneEndGPU( a(*it) ), begin, drift );
                const auto nsnext = nend - m_vd.zvStart;
                if( nsnext < 0 || nsnext - px1ns >= MinVisNs * 2 ) break;
                px1ns = nsnext;
                rend = nend;
                nextTime = nend + nspx;
            }
            const auto px1 = px1ns * pxns;
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ), color );
            DrawZigZag( draw, wpos + ImVec2( 0, offset + ty/2 ), std::max( px0, -10.0 ), std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), ty/4, DarkenColor( color ) );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty + 1 ) ) )
            {
                if( num > 1 )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Zones too small to display:", RealToString( num ) );
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( rend - start ) );
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 2 ) && rend - start > 0 )
                    {
                        ZoomToRange( start, rend );
                    }
                }
                else
                {
                    ZoneTooltipGPU( { &ev.event, ctx } );

                    if( IsMouseClicked( 2 ) && rend - start > 0 )
                    {
                        ZoomToZoneGPU( { &ev.event, ctx } );
                    }
                    if( IsMouseClicked( 0 ) )
                    {
                        ShowZoneInfo( { &ev.event, ctx }, zoneThread );
                    }

                    m_gpuThread = zoneThread;
                    m_gpuStart = ev.CpuStart();
                    m_gpuEnd = ev.CpuEnd();
                }
            }
            const auto tmp = RealToString( num );
            const auto tsz = ImGui::CalcTextSize( tmp );
            if( tsz.x < px1 - px0 )
            {
                const auto x = px0 + ( px1 - px0 - tsz.x ) / 2;
                DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
            }
        }
        else
        {
            if( ev.Child() >= 0 )
            {
                const auto d = DispatchGpuZoneLevel( m_worker.GetGpuChildren( ev.Child() ), hover, pxns, nspx, wpos, _offset, depth, ctx, yMin, yMax, begin, drift );
                if( d > maxdepth ) maxdepth = d;
            }

            const char* zoneName = m_worker.GetZoneName( ev );
            auto tsz = ImGui::CalcTextSize( zoneName );

            const auto pr0 = ( start - m_vd.zvStart ) * pxns;
            const auto pr1 = ( end - m_vd.zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );
            const auto zoneColor = GetZoneColorData( { &ev.event, ctx }, zoneThread, depth, 0 );
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
                const auto x = ( start - m_vd.zvStart ) * pxns + ( ( end - start ) * pxns - tsz.x ) / 2;
                if( x < 0 || x > w - tsz.x )
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, zoneName );
                    ImGui::PopClipRect();
                }
                else if( ev.GpuStart() == ev.GpuEnd() )
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
                DrawTextContrast( draw, wpos + ImVec2( ( start - m_vd.zvStart ) * pxns, offset ), 0xFFFFFFFF, zoneName );
                ImGui::PopClipRect();
            }

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y + 1 ) ) )
            {
                ZoneTooltipGPU( { &ev.event, ctx } );

                if( !m_zoomAnim.active && IsMouseClicked( 2 ) )
                {
                    ZoomToZoneGPU( { &ev.event, ctx } );
                }
                if( IsMouseClicked( 0 ) )
                {
                    ShowZoneInfo( { &ev.event, ctx }, zoneThread );
                }

                m_gpuThread = zoneThread;
                m_gpuStart = ev.CpuStart();
                m_gpuEnd = ev.CpuEnd();
            }

            ++it;
        }
    }
    return maxdepth;
}

template<typename Adapter, typename V>
int View::SkipGpuZoneLevel( const V& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, const GpuCtxData* ctx, float yMin, float yMax, int64_t begin, int drift )
{
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, m_vd.zvStart ), [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).End(), begin, drift ) < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    Adapter a;

    const auto zitend = std::lower_bound( it, vec.end(), std::max<int64_t>( 0, m_vd.zvEnd ), [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).Start(), begin, drift ) < (uint64_t)r; } );
    if( it == zitend ) return depth;
    if( AdjustGpuTime( a(*(zitend-1)).End(), begin, drift ) < m_vd.zvStart ) return depth;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = a(*it);
        auto end = m_worker.GetZoneEndGPU( ev );
        if( end == std::numeric_limits<int64_t>::max() ) break;
        const auto start = AdjustGpuTime( ev.Start(), begin, drift );
        end = AdjustGpuTime( end, begin, drift );
        const auto zsz = std::max( ( end - start ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            const auto MinVisNs = MinVisSize * nspx;
            auto px1ns = end - m_vd.zvStart;
            auto nextTime = end + MinVisNs;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, nextTime, [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).End(), begin, drift ) < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                if( it == zitend ) break;
                const auto nend = AdjustGpuTime( m_worker.GetZoneEndGPU( a(*it) ), begin, drift );
                const auto nsnext = nend - m_vd.zvStart;
                if( nsnext - px1ns >= MinVisNs * 2 ) break;
                px1ns = nsnext;
                nextTime = nend + nspx;
            }
        }
        else
        {
            if( ev.Child() >= 0 )
            {
                const auto d = DispatchGpuZoneLevel( m_worker.GetGpuChildren( ev.Child() ), hover, pxns, nspx, wpos, _offset, depth, ctx, yMin, yMax, begin, drift );
                if( d > maxdepth ) maxdepth = d;
            }
            ++it;
        }
    }
    return maxdepth;
}

}
