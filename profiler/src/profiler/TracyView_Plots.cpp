#include <inttypes.h>

#include "TracyColor.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"

namespace tracy
{

bool View::DrawPlot( const TimelineContext& ctx, PlotData& plot, const std::vector<uint32_t>& plotDraw, int& offset )
{
    auto draw = ImGui::GetWindowDrawList();
    const auto& wpos = ctx.wpos;
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto pxns = ctx.pxns;
    const auto w = ctx.w;
    const auto hover = ctx.hover;
    const auto ty = ctx.ty;

    const auto PlotHeight = m_vd.plotHeight * GetScale();

    auto yPos = wpos.y + offset;
    if( yPos + PlotHeight >= ctx.yMin && yPos <= ctx.yMax )
    {
        auto min = plot.rMin;
        auto max = plot.rMax;

        auto pvit = m_plotView.find( &plot );
        if( pvit == m_plotView.end() )
        {
            pvit = m_plotView.emplace( &plot, PlotView { min, max } ).first;
        }
        auto& pv = pvit->second;
        if( pv.min != min || pv.max != max )
        {
            const auto dt = ImGui::GetIO().DeltaTime;
            const auto minDiff = min - pv.min;
            const auto maxDiff = max - pv.max;

            pv.min += minDiff * 15.0 * dt;
            pv.max += maxDiff * 15.0 * dt;

            const auto minDiffNew = min - pv.min;
            const auto maxDiffNew = max - pv.max;

            if( minDiff * minDiffNew < 0 ) pv.min = min;
            if( maxDiff * maxDiffNew < 0 ) pv.max = max;

            min = pv.min;
            max = pv.max;
        }

        const auto color = GetPlotColor( plot, m_worker );
        const auto bg = 0x22000000 | ( DarkenColorMore( color ) & 0xFFFFFF );
        const auto fill = 0x22000000 | ( DarkenColor( color ) & 0xFFFFFF );

        draw->AddRectFilled( ImVec2( 0, yPos ), ImVec2( w, yPos + PlotHeight ), bg );

        const auto revrange = 1.0 / ( max - min );

        auto it = plotDraw.begin();
        auto end = plotDraw.end();
        double px, py;
        bool first = true;
        while( it < end )
        {
            auto& vec = plot.data;
            const auto cnt = *it++;
            const auto i0 = *it++;
            const auto& v0 = vec[i0];
            double x = ( v0.time.Val() - m_vd.zvStart ) * pxns;
            double y = PlotHeight - ( v0.val - min ) * revrange * PlotHeight;

            if( first )
            {
                first = false;
            }
            else
            {
                if( plot.showSteps )
                {
                    if( plot.fill )
                    {
                        draw->AddRectFilled( dpos + ImVec2( px, offset + PlotHeight ), dpos + ImVec2( x, offset + py ), fill );
                    }
                    const ImVec2 data[3] = { dpos + ImVec2( px, offset + py ), dpos + ImVec2( x, offset + py ), dpos + ImVec2( x, offset + y ) };
                    draw->AddPolyline( data, 3, color, 0, 1.0f );
                }
                else
                {
                    if( plot.fill )
                    {
                        draw->AddQuadFilled( dpos + ImVec2( px, offset + PlotHeight ), dpos + ImVec2( px, offset + py ), dpos + ImVec2( x, offset + y ), dpos + ImVec2( x, offset + PlotHeight ), fill );
                    }
                    DrawLine( draw, dpos + ImVec2( px, offset + py ), dpos + ImVec2( x, offset + y ), color );
                }
            }

            if( cnt == 0 )
            {
                if( i0 == 0 )
                {
                    DrawPlotPoint( wpos, x, y, offset, color, hover, false, v0, 0, plot.type, plot.format, PlotHeight, plot.name );
                }
                else
                {
                    DrawPlotPoint( wpos, x, y, offset, color, hover, true, v0, vec[i0-1].val, plot.type, plot.format, PlotHeight, plot.name );
                }
                px = x;
                py = y;
            }
            else
            {
                constexpr int MaxShow = 32;
                const auto i1 = i0 + cnt - 1;
                const auto& v1 = vec[i1];
                px = x;
                py = PlotHeight - ( v1.val - min ) * revrange * PlotHeight;
                const auto imin = *it++;
                const auto imax = *it++;
                const auto vmin = vec[imin].val;
                const auto vmax = vec[imax].val;
                const auto ymin = offset + PlotHeight - ( vmin - min ) * revrange * PlotHeight;
                const auto ymax = offset + PlotHeight - ( vmax - min ) * revrange * PlotHeight;
                if( cnt < MaxShow )
                {
                    DrawLine( draw, dpos + ImVec2( x, ymin ), dpos + ImVec2( x, ymax ), color );

                    for( int i=0; i<cnt; i++ )
                    {
                        const auto is = i0 + i;
                        const auto& vs = vec[is];
                        auto ys = PlotHeight - ( vs.val - min ) * revrange * PlotHeight;
                        DrawPlotPoint( wpos, x, ys, offset, color, hover, vs.val, plot.format, PlotHeight );
                    }
                }
                else
                {
                    if( ymin - ymax < 3 )
                    {
                        const auto mid = ( ymin + ymax ) * 0.5;
                        DrawLine( draw, dpos + ImVec2( x, mid - 1.5 ), dpos + ImVec2( x, mid + 1.5 ), color, 3 );
                    }
                    else
                    {
                        DrawLine( draw, dpos + ImVec2( x, ymin ), dpos + ImVec2( x, ymax ), color, 3 );
                    }

                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x - 2, offset ), wpos + ImVec2( x + 2, offset + PlotHeight ) ) )
                    {
                        constexpr int NumSamples = 256;
                        ImGui::BeginTooltip();
                        TextFocused( "Number of values:", RealToString( cnt ) );
                        if( cnt < NumSamples )
                        {
                            TextDisabledUnformatted( "Range:" );
                        }
                        else
                        {
                            TextDisabledUnformatted( "Estimated range:" );
                        }
                        ImGui::SameLine();
                        ImGui::Text( "%s - %s", FormatPlotValue( vmin, plot.format ), FormatPlotValue( vmax, plot.format ) );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%s)", FormatPlotValue( vmax - vmin, plot.format ) );
                        ImGui::EndTooltip();
                    }
                }
            }
        }

        auto tmp = FormatPlotValue( plot.rMax, plot.format );
        DrawTextSuperContrast( draw, wpos + ImVec2( 0, offset ), color, tmp );
        offset += PlotHeight - ty;
        tmp = FormatPlotValue( plot.rMin, plot.format );
        DrawTextSuperContrast( draw, wpos + ImVec2( 0, offset ), color, tmp );

        DrawLine( draw, dpos + ImVec2( 0, offset + ty - 1 ), dpos + ImVec2( w, offset + ty - 1 ), 0xFF226E6E );
        offset += ty;

        if( plot.type == PlotType::Memory )
        {
            auto& mem = m_worker.GetMemoryNamed( plot.name );

            if( m_memoryAllocInfoPool == plot.name && m_memoryAllocInfoWindow >= 0 )
            {
                const auto& ev = mem.data[m_memoryAllocInfoWindow];

                const auto tStart = ev.TimeAlloc();
                const auto tEnd = ev.TimeFree() < 0 ? m_worker.GetLastTime() : ev.TimeFree();

                const auto px0 = ( tStart - m_vd.zvStart ) * pxns;
                const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( tEnd - m_vd.zvStart ) * pxns );
                draw->AddRectFilled( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x2288DD88 );
                draw->AddRect( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x4488DD88 );
            }
            if( m_memoryAllocHover >= 0 && m_memoryAllocHoverPool == plot.name && ( m_memoryAllocInfoPool != plot.name || m_memoryAllocHover != m_memoryAllocInfoWindow ) )
            {
                const auto& ev = mem.data[m_memoryAllocHover];

                const auto tStart = ev.TimeAlloc();
                const auto tEnd = ev.TimeFree() < 0 ? m_worker.GetLastTime() : ev.TimeFree();

                const auto px0 = ( tStart - m_vd.zvStart ) * pxns;
                const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( tEnd - m_vd.zvStart ) * pxns );
                draw->AddRectFilled( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x228888DD );
                draw->AddRect( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x448888DD );

                if( m_memoryAllocHoverWait > 0 )
                {
                    m_memoryAllocHoverWait--;
                }
                else
                {
                    m_memoryAllocHover = -1;
                }
            }
        }
    }
    else
    {
        offset += PlotHeight;
    }
    return true;
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, double val, PlotValueFormatting format, float PlotHeight )
{
    auto draw = ImGui::GetWindowDrawList();
    draw->AddRect( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );

    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x - 2, offset ), wpos + ImVec2( x + 2, offset + PlotHeight ) ) )
    {
        ImGui::BeginTooltip();
        TextFocused( "Value:", FormatPlotValue( val, format ) );
        ImGui::EndTooltip();
    }
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, const PlotItem& item, double prev, PlotType type, PlotValueFormatting format, float PlotHeight, uint64_t name )
{
    auto draw = ImGui::GetWindowDrawList();
    draw->AddRect( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );

    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x - 2, offset ), wpos + ImVec2( x + 2, offset + PlotHeight ) ) )
    {
        ImGui::BeginTooltip();
        TextFocused( "Time:", TimeToStringExact( item.time.Val() ) );
        if( type == PlotType::Memory )
        {
            TextDisabledUnformatted( "Value:" );
            ImGui::SameLine();
            if( item.val < 10000ll )
            {
                ImGui::TextUnformatted( MemSizeToString( item.val ) );
            }
            else
            {
                ImGui::TextUnformatted( MemSizeToString( item.val ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( item.val ) );
            }
        }
        else
        {
            TextFocused( "Value:", FormatPlotValue( item.val, format ) );
        }
        if( hasPrev )
        {
            const auto change = item.val - prev;
            TextFocused( "Change:", FormatPlotValue( change, format ) );

            if( type == PlotType::Memory )
            {
                auto& mem = m_worker.GetMemoryNamed( name );
                const MemEvent* ev = nullptr;
                if( change > 0 )
                {
                    auto it = std::lower_bound( mem.data.begin(), mem.data.end(), item.time.Val(), [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
                    if( it != mem.data.end() && it->TimeAlloc() == item.time.Val() )
                    {
                        ev = it;
                    }
                }
                else
                {
                    const auto& data = mem.data;
                    auto it = std::lower_bound( mem.frees.begin(), mem.frees.end(), item.time.Val(), [&data] ( const auto& lhs, const auto& rhs ) { return data[lhs].TimeFree() < rhs; } );
                    if( it != mem.frees.end() && data[*it].TimeFree() == item.time.Val() )
                    {
                        ev = &data[*it];
                    }
                }
                if( ev )
                {
                    ImGui::Separator();
                    TextDisabledUnformatted( "Address:" );
                    ImGui::SameLine();
                    ImGui::Text( "0x%" PRIx64, ev->Ptr() );
                    TextFocused( "Appeared at", TimeToStringExact( ev->TimeAlloc() ) );
                    if( change > 0 )
                    {
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(this event)" );
                    }
                    if( ev->TimeFree() < 0 )
                    {
                        ImGui::TextUnformatted( "Allocation still active" );
                    }
                    else
                    {
                        TextFocused( "Freed at", TimeToStringExact( ev->TimeFree() ) );
                        if( change < 0 )
                        {
                            ImGui::SameLine();
                            TextDisabledUnformatted( "(this event)" );
                        }
                        TextFocused( "Duration:", TimeToString( ev->TimeFree() - ev->TimeAlloc() ) );
                    }
                    uint64_t tid;
                    if( change > 0 )
                    {
                        tid = m_worker.DecompressThread( ev->ThreadAlloc() );
                    }
                    else
                    {
                        tid = m_worker.DecompressThread( ev->ThreadFree() );
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
                    m_memoryAllocHover = std::distance( mem.data.begin(), ev );
                    m_memoryAllocHoverWait = 2;
                    m_memoryAllocHoverPool = name;
                    if( IsMouseClicked( 0 ) )
                    {
                        m_memoryAllocInfoWindow = m_memoryAllocHover;
                        m_memoryAllocInfoPool = name;
                    }
                }
            }
        }
        ImGui::EndTooltip();
    }
}

}
