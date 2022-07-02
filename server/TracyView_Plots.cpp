#include <inttypes.h>

#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

const char* View::GetPlotName( const PlotData* plot ) const
{
    static char tmp[1024];
    switch( plot->type )
    {
    case PlotType::User:
        return m_worker.GetString( plot->name );
    case PlotType::Memory:
        if( plot->name == 0 )
        {
            return ICON_FA_MEMORY " Memory usage";
        }
        else
        {
            sprintf( tmp, ICON_FA_MEMORY " %s", m_worker.GetString( plot->name ) );
            return tmp;
        }
    case PlotType::SysTime:
        return ICON_FA_TACHOMETER_ALT " CPU usage";
    default:
        assert( false );
        return nullptr;
    }
}

static const char* FormatPlotValue( double val, PlotValueFormatting format )
{
    static char buf[64];
    switch( format )
    {
    case PlotValueFormatting::Number:
        return RealToString( val );
        break;
    case PlotValueFormatting::Memory:
        return MemSizeToString( val );
        break;
    case PlotValueFormatting::Percentage:
        sprintf( buf, "%.2f%%", val );
        break;
    default:
        assert( false );
        break;
    }
    return buf;
}

int View::DrawPlots( int offset, double pxns, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    const auto PlotHeight = 100 * GetScale();

    enum { MaxPoints = 128 };
    float tmpvec[MaxPoints*2];

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    auto draw = ImGui::GetWindowDrawList();
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;
    const auto nspx = 1.0 / pxns;
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    for( const auto& v : m_worker.GetPlots() )
    {
        auto& vis = Vis( v );
        if( !vis.visible )
        {
            vis.height = 0;
            vis.offset = 0;
            continue;
        }
        if( v->data.empty() ) continue;
        bool& showFull = vis.showFull;

        float txtx = 0;
        const auto yPos = AdjustThreadPosition( vis, wpos.y, offset );
        const auto oldOffset = offset;
        ImGui::PushClipRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + vis.height ), true );
        if( yPos + ty >= yMin && yPos <= yMax )
        {
            if( showFull )
            {
                draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), 0xFF44DDDD );
            }
            else
            {
                draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), 0xFF226E6E, 2.0f );
            }
            const auto txt = GetPlotName( v );
            txtx = ImGui::CalcTextSize( txt ).x;
            DrawTextContrast( draw, wpos + ImVec2( ty, offset ), showFull ? 0xFF44DDDD : 0xFF226E6E, txt );
            DrawLine( draw, dpos + ImVec2( 0, offset + ty - 1 ), dpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtx, offset + ty ) ) )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "Plot \"%s\"", txt );
                ImGui::Separator();

                const auto first = v->data.front().time.Val();
                const auto last = v->data.back().time.Val();
                const auto activity = last - first;
                const auto traceLen = m_worker.GetLastTime();

                TextFocused( "Appeared at", TimeToString( first ) );
                TextFocused( "Last event at", TimeToString( last ) );
                TextFocused( "Activity time:", TimeToString( activity ) );
                ImGui::SameLine();
                char buf[64];
                PrintStringPercent( buf, activity / double( traceLen ) * 100 );
                TextDisabledUnformatted( buf );
                ImGui::Separator();
                TextFocused( "Data points:", RealToString( v->data.size() ) );
                TextFocused( "Data range:", FormatPlotValue( v->max - v->min, v->format ) );
                TextFocused( "Min value:", FormatPlotValue( v->min, v->format ) );
                TextFocused( "Max value:", FormatPlotValue( v->max, v->format ) );
                TextFocused( "Avg value:", FormatPlotValue( v->sum / v->data.size(), v->format ) );
                TextFocused( "Data/second:", RealToString( double( v->data.size() ) / activity * 1000000000ll ) );

                const auto it = std::lower_bound( v->data.begin(), v->data.end(), last - 1000000000ll * 10, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
                const auto tr10 = last - it->time.Val();
                if( tr10 != 0 )
                {
                    TextFocused( "D/s (10s):", RealToString( double( std::distance( it, v->data.end() ) ) / tr10 * 1000000000ll ) );
                }
                ImGui::EndTooltip();

                if( IsMouseClicked( 0 ) )
                {
                    showFull = !showFull;
                }
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToRange( first, last );
                }
            }
        }

        offset += ty;

        if( showFull )
        {
            auto yPos = wpos.y + offset;
            if( yPos + PlotHeight >= yMin && yPos <= yMax )
            {
                auto& vec = v->data;
                vec.ensure_sorted();

                if( v->type == PlotType::Memory )
                {
                    auto& mem = m_worker.GetMemoryNamed( v->name );

                    if( m_memoryAllocInfoPool == v->name && m_memoryAllocInfoWindow >= 0 )
                    {
                        const auto& ev = mem.data[m_memoryAllocInfoWindow];

                        const auto tStart = ev.TimeAlloc();
                        const auto tEnd = ev.TimeFree() < 0 ? m_worker.GetLastTime() : ev.TimeFree();

                        const auto px0 = ( tStart - m_vd.zvStart ) * pxns;
                        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( tEnd - m_vd.zvStart ) * pxns );
                        draw->AddRectFilled( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x2288DD88 );
                        draw->AddRect( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x4488DD88 );
                    }
                    if( m_memoryAllocHover >= 0 && m_memoryAllocHoverPool == v->name && ( m_memoryAllocInfoPool != v->name || m_memoryAllocHover != m_memoryAllocInfoWindow ) )
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

                auto it = std::lower_bound( vec.begin(), vec.end(), m_vd.zvStart - m_worker.GetDelay(), [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
                auto end = std::lower_bound( it, vec.end(), m_vd.zvEnd + m_worker.GetResolution(), [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );

                if( end != vec.end() ) end++;
                if( it != vec.begin() ) it--;

                double min = it->val;
                double max = it->val;
                const auto num = std::distance( it, end );
                if( num > 1000000 )
                {
                    min = v->min;
                    max = v->max;
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

                const auto rMin = min;
                const auto rMax = max;

                auto pvit = m_plotView.find( v );
                if( pvit == m_plotView.end() )
                {
                    pvit = m_plotView.emplace( v, PlotView { min, max } ).first;
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
                    DrawPlotPoint( wpos, x, y, offset, 0xFF44DDDD, hover, false, it, 0, false, v->type, v->format, PlotHeight, v->name );
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

                    DrawLine( draw, dpos + ImVec2( x0, offset + y0 ), dpos + ImVec2( x1, offset + y1 ), 0xFF44DDDD );

                    const auto rx = skip == 0 ? 2.0 : ( skip == 1 ? 2.5 : 4.0 );

                    auto range = std::upper_bound( it, end, int64_t( it->time.Val() + nspx * rx ), [] ( const auto& l, const auto& r ) { return l < r.time.Val(); } );
                    assert( range > it );
                    const auto rsz = std::distance( it, range );
                    if( rsz == 1 )
                    {
                        DrawPlotPoint( wpos, x1, y1, offset, 0xFF44DDDD, hover, true, it, prevy->val, false, v->type, v->format, PlotHeight, v->name );
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
                            DrawLine( draw, dpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), dpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), 0xFF44DDDD, 4.f );

                            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x1 - 2, offset ), wpos + ImVec2( x1 + 2, offset + PlotHeight ) ) )
                            {
                                ImGui::BeginTooltip();
                                TextFocused( "Number of values:", RealToString( rsz ) );
                                TextDisabledUnformatted( "Estimated range:" );
                                ImGui::SameLine();
                                ImGui::Text( "%s - %s", FormatPlotValue( tmpvec[0], v->format ), FormatPlotValue( dst[-1], v->format ) );
                                ImGui::SameLine();
                                ImGui::TextDisabled( "(%s)", FormatPlotValue( dst[-1] - tmpvec[0], v->format ) );
                                ImGui::EndTooltip();
                            }
                        }
                        else
                        {
                            DrawLine( draw, dpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), dpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), 0xFF44DDDD );

                            auto vit = tmpvec;
                            while( vit != dst )
                            {
                                auto vrange = std::upper_bound( vit, dst, *vit + 3.0 / ( revrange * PlotHeight ), [] ( const auto& l, const auto& r ) { return l < r; } );
                                assert( vrange > vit );
                                if( std::distance( vit, vrange ) == 1 )
                                {
                                    DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, false, v->format, PlotHeight );
                                }
                                else
                                {
                                    DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, true, v->format, PlotHeight );
                                }
                                vit = vrange;
                            }
                        }

                        prevy = it - 1;
                    }
                }

                if( yPos + ty >= yMin && yPos <= yMax )
                {
                    char tmp[64];
                    sprintf( tmp, "(y-range: %s, visible data points: %s)", FormatPlotValue( rMax - rMin, v->format ), RealToString( num ) );
                    draw->AddText( wpos + ImVec2( ty * 1.5f + txtx, offset - ty ), 0x8844DDDD, tmp );
                }
                auto tmp = FormatPlotValue( rMax, v->format );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );
                offset += PlotHeight - ty;
                tmp = FormatPlotValue( rMin, v->format );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );

                DrawLine( draw, dpos + ImVec2( 0, offset + ty - 1 ), dpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );
                offset += ty;
            }
            else
            {
                offset += PlotHeight;
            }
        }
        offset += 0.2 * ty;
        AdjustThreadHeight( vis, oldOffset, offset );
        ImGui::PopClipRect();
    }

    return offset;
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
