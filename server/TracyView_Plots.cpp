#include <inttypes.h>

#include "TracyColor.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"

namespace tracy
{

bool View::DrawPlot( PlotData& plot, double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    const auto PlotHeight = 100 * GetScale();

    enum { MaxPoints = 128 };
    float tmpvec[MaxPoints*2];

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    auto draw = ImGui::GetWindowDrawList();
    const auto nspx = 1.0 / pxns;
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    auto& vec = plot.data;
    vec.ensure_sorted();
    if( vec.front().time.Val() > m_vd.zvEnd || vec.back().time.Val() < m_vd.zvStart ) return false;

    auto yPos = wpos.y + offset;
    if( yPos + PlotHeight >= yMin && yPos <= yMax )
    {
        const auto color = GetPlotColor( plot, m_worker );
        const auto bg = 0x22000000 | ( DarkenColorMore( color ) & 0xFFFFFF );
        const auto fill = 0x22000000 | ( DarkenColor( color ) & 0xFFFFFF );

        draw->AddRectFilled( ImVec2( 0, yPos ), ImVec2( w, yPos + PlotHeight ), bg );

        auto it = std::lower_bound( vec.begin(), vec.end(), m_vd.zvStart - m_worker.GetDelay(), [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
        auto end = std::lower_bound( it, vec.end(), m_vd.zvEnd + m_worker.GetResolution(), [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );

        if( end != vec.end() ) end++;
        if( it != vec.begin() ) it--;

        double min = it->val;
        double max = it->val;
        const auto num = std::distance( it, end );
        if( num > 1000000 )
        {
            min = plot.min;
            max = plot.max;
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
        }
        if( min == max )
        {
            min--;
            max++;
        }

        plot.rMin = min;
        plot.rMax = max;
        plot.num = num;

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

        const auto revrange = 1.0 / ( max - min );

        if( it == vec.begin() )
        {
            const auto x = ( it->time.Val() - m_vd.zvStart ) * pxns;
            const auto y = PlotHeight - ( it->val - min ) * revrange * PlotHeight;
            DrawPlotPoint( wpos, x, y, offset, color, hover, false, it, 0, false, plot.type, plot.format, PlotHeight, plot.name );
        }

        auto prevx = it;
        auto prevy = it;
        ++it;
        ptrdiff_t skip = 0;
        while( it < end )
        {
            const auto x0 = ( prevx->time.Val() - m_vd.zvStart ) * pxns;
            const auto x1 = ( it->time.Val() - m_vd.zvStart ) * pxns;
            const auto y0 = PlotHeight - ( prevy->val - min ) * revrange * PlotHeight;
            const auto y1 = PlotHeight - ( it->val - min ) * revrange * PlotHeight;

            if( plot.showSteps )
            {
                if( plot.fill )
                {
                    draw->AddRectFilled( dpos + ImVec2( x0, offset + PlotHeight ), dpos + ImVec2( x1, offset + y0 ), fill );
                }
                const ImVec2 data[3] = { dpos + ImVec2( x0, offset + y0 ), dpos + ImVec2( x1, offset + y0 ), dpos + ImVec2( x1, offset + y1 ) };
                draw->AddPolyline( data, 3, color, 0, 1.0f );
            }
            else
            {
                if( plot.fill )
                {
                    draw->AddQuadFilled( dpos + ImVec2( x0, offset + PlotHeight ), dpos + ImVec2( x0, offset + y0 ), dpos + ImVec2( x1, offset + y1 ), dpos + ImVec2( x1, offset + PlotHeight ), fill );
                }
                DrawLine( draw, dpos + ImVec2( x0, offset + y0 ), dpos + ImVec2( x1, offset + y1 ), color );
            }

            const auto rx = skip == 0 ? 2.0 : ( skip == 1 ? 2.5 : 4.0 );

            auto range = std::upper_bound( it, end, int64_t( it->time.Val() + nspx * rx ), [] ( const auto& l, const auto& r ) { return l < r.time.Val(); } );
            assert( range > it );
            const auto rsz = std::distance( it, range );
            if( rsz == 1 )
            {
                DrawPlotPoint( wpos, x1, y1, offset, color, hover, true, it, prevy->val, false, plot.type, plot.format, PlotHeight, plot.name );
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
                const auto rsz = std::distance( it, range );
                const auto ssz = rsz / skip1;
                for( int64_t i=0; i<ssz; i++ )
                {
                    *dst++ = float( it->val );
                    it += skip1;
                }
                pdqsort_branchless( tmpvec, dst );

                if( rsz > MaxPoints )
                {
                    DrawLine( draw, dpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), dpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), color, 4.f );

                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x1 - 2, offset ), wpos + ImVec2( x1 + 2, offset + PlotHeight ) ) )
                    {
                        ImGui::BeginTooltip();
                        TextFocused( "Number of values:", RealToString( rsz ) );
                        TextDisabledUnformatted( "Estimated range:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s - %s", FormatPlotValue( tmpvec[0], plot.format ), FormatPlotValue( dst[-1], plot.format ) );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%s)", FormatPlotValue( dst[-1] - tmpvec[0], plot.format ) );
                        ImGui::EndTooltip();
                    }
                }
                else
                {
                    DrawLine( draw, dpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), dpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), color );

                    auto vit = tmpvec;
                    while( vit != dst )
                    {
                        auto vrange = std::upper_bound( vit, dst, *vit + 3.0 / ( revrange * PlotHeight ), [] ( const auto& l, const auto& r ) { return l < r; } );
                        assert( vrange > vit );
                        if( std::distance( vit, vrange ) == 1 )
                        {
                            DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, color, hover, false, *vit, 0, false, plot.format, PlotHeight );
                        }
                        else
                        {
                            DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, color, hover, false, *vit, 0, true, plot.format, PlotHeight );
                        }
                        vit = vrange;
                    }
                }

                prevy = it - 1;
            }
        }

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

        auto tmp = FormatPlotValue( plot.rMax, plot.format );
        DrawTextSuperContrast( draw, wpos + ImVec2( 0, offset ), color, tmp );
        offset += PlotHeight - ty;
        tmp = FormatPlotValue( plot.rMin, plot.format );
        DrawTextSuperContrast( draw, wpos + ImVec2( 0, offset ), color, tmp );

        DrawLine( draw, dpos + ImVec2( 0, offset + ty - 1 ), dpos + ImVec2( w, offset + ty - 1 ), 0xFF226E6E );
        offset += ty;
    }
    else
    {
        offset += PlotHeight;
    }
    return true;
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged, PlotValueFormatting format, float PlotHeight )
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
        TextFocused( "Value:", FormatPlotValue( val, format ) );
        if( hasPrev )
        {
            TextFocused( "Change:", FormatPlotValue( val - prev, format ) );
        }
        ImGui::EndTooltip();
    }
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, const PlotItem* item, double prev, bool merged, PlotType type, PlotValueFormatting format, float PlotHeight, uint64_t name )
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
        TextFocused( "Time:", TimeToStringExact( item->time.Val() ) );
        if( type == PlotType::Memory )
        {
            TextDisabledUnformatted( "Value:" );
            ImGui::SameLine();
            if( item->val < 10000ll )
            {
                ImGui::TextUnformatted( MemSizeToString( item->val ) );
            }
            else
            {
                ImGui::TextUnformatted( MemSizeToString( item->val ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( item->val ) );
            }
        }
        else
        {
            TextFocused( "Value:", FormatPlotValue( item->val, format ) );
        }
        if( hasPrev )
        {
            const auto change = item->val - prev;
            TextFocused( "Change:", FormatPlotValue( change, format ) );

            if( type == PlotType::Memory )
            {
                auto& mem = m_worker.GetMemoryNamed( name );
                const MemEvent* ev = nullptr;
                if( change > 0 )
                {
                    auto it = std::lower_bound( mem.data.begin(), mem.data.end(), item->time.Val(), [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
                    if( it != mem.data.end() && it->TimeAlloc() == item->time.Val() )
                    {
                        ev = it;
                    }
                }
                else
                {
                    const auto& data = mem.data;
                    auto it = std::lower_bound( mem.frees.begin(), mem.frees.end(), item->time.Val(), [&data] ( const auto& lhs, const auto& rhs ) { return data[lhs].TimeFree() < rhs; } );
                    if( it != mem.frees.end() && data[*it].TimeFree() == item->time.Val() )
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
