#include <inttypes.h>
#include <math.h>

#include "TracyColor.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineDraw.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"

namespace tracy
{

bool View::DrawPlot( const TimelineContext& ctx, PlotData& plot, const std::vector<uint32_t>& plotDraw, const PlotSpectrogram* spectrogram, int& offset, bool rightEnd )
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

        if( spectrogram )
        {
            DrawPlotSpectrogram( ctx, plot, *spectrogram, offset, PlotHeight, min, max, color );
        }

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
                    draw->AddPolyline( data, 3, color, 1.0f );
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

        if( rightEnd )
        {
            const auto lastTime = m_worker.GetLastTime();
            if( lastTime > m_vd.zvStart )
            {
                double y;
                double x0 = 0;
                const auto x1 = std::min<double>( ( lastTime - m_vd.zvStart ) * pxns, w );

                if( plotDraw.empty() && !spectrogram )
                {
                    y = PlotHeight * 0.5;
                    DrawLine( draw, dpos + ImVec2( 0, offset + y ), dpos + ImVec2( x1, offset + y ), color );
                }
                else
                {
                    x0 = ( plot.data.back().time.Val() - m_vd.zvStart ) * pxns;
                    y = PlotHeight - ( plot.data.back().val - min ) * revrange * PlotHeight;
                    DrawLine( draw, dpos + ImVec2( x0, offset + y ), dpos + ImVec2( x1, offset + y ), color );
                }

                if( plot.fill && !spectrogram )
                {
                    draw->AddRectFilled( dpos + ImVec2( x0, offset + PlotHeight ), dpos + ImVec2( x1, offset + y ), fill );
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

// Round a value to one decimal digit finer than the given step, so that bin
// bounds derived from floating point arithmetic print without noise.
static double RoundToStep( double v, double step )
{
    const auto k = int( 1 - floor( log10( step ) ) );
    if( k > 0 )
    {
        const auto m = pow( 10.0, k );
        return round( v * m ) / m;
    }
    else
    {
        const auto m = pow( 10.0, -k );
        return round( v / m ) * m;
    }
}

static uint32_t LerpColor( uint32_t c0, uint32_t c1, float t )
{
    const auto r = int( ( ( c0       ) & 0xFF ) + ( int( ( c1       ) & 0xFF ) - int( ( c0       ) & 0xFF ) ) * t );
    const auto g = int( ( ( c0 >> 8  ) & 0xFF ) + ( int( ( c1 >> 8  ) & 0xFF ) - int( ( c0 >> 8  ) & 0xFF ) ) * t );
    const auto b = int( ( ( c0 >> 16 ) & 0xFF ) + ( int( ( c1 >> 16 ) & 0xFF ) - int( ( c0 >> 16 ) & 0xFF ) ) * t );
    return 0xFF000000 | ( b << 16 ) | ( g << 8 ) | r;
}

void View::DrawPlotSpectrogram( const TimelineContext& ctx, const PlotData& plot, const PlotSpectrogram& sp, int offset, float PlotHeight, double min, double max, uint32_t color )
{
    if( sp.max == 0 ) return;

    auto draw = ImGui::GetWindowDrawList();
    const auto& wpos = ctx.wpos;
    const auto w = sp.w;
    const auto h = sp.h;

    // Lightness ramp: dark plot color -> plot color -> almost white.
    constexpr int NumLevels = 64;
    uint32_t palette[NumLevels];
    const auto dark = DarkenColorHalf( color );
    const auto light = LerpColor( color, 0xFFFFFFFF, 0.8f );
    for( int i=0; i<NumLevels; i++ )
    {
        const auto t = float( i ) / ( NumLevels - 1 );
        palette[i] = t < 0.5f ? LerpColor( dark, color, t * 2 ) : LerpColor( color, light, ( t - 0.5f ) * 2 );
    }

    // Bin counts are mapped to lightness on a logarithmic scale. A floor
    // keeps single hits visible against the background.
    constexpr double LevelFloor = 0.2;
    const auto invLogMax = 1.0 / log1p( double( sp.max ) );
    auto CountToLevel = [&] ( uint32_t cnt ) {
        const auto t = LevelFloor + ( 1 - LevelFloor ) * log1p( double( cnt ) ) * invLogMax;
        return std::min( NumLevels - 1, int( t * ( NumLevels - 1 ) + 0.5 ) );
    };
    constexpr uint32_t LutSize = 1024;
    uint8_t levelLut[LutSize];
    const auto lutSize = std::min( LutSize, sp.max + 1 );
    for( uint32_t i=1; i<lutSize; i++ )
    {
        levelLut[i] = uint8_t( CountToLevel( i ) );
    }
    auto Level = [&] ( uint32_t cnt ) -> int {
        if( cnt == 0 ) return -1;
        if( cnt < lutSize ) return levelLut[cnt];
        return CountToLevel( cnt );
    };

    // Bins are laid out in the target value range, but displayed in the
    // (possibly animating) current range, so map through values.
    const auto step = ( plot.rMax - plot.rMin ) / h;
    const auto revrange = 1.0 / ( max - min );
    const auto yTop = wpos.y + offset;
    const auto yBottom = yTop + PlotHeight;
    auto RowToY = [&] ( int row ) {
        const auto v = plot.rMin + row * step;
        const auto y = yBottom - ( v - min ) * revrange * PlotHeight;
        return float( std::clamp<double>( y, yTop, yBottom ) );
    };

    const auto bins = sp.bins.data();
    for( int x=0; x<w; x++ )
    {
        const auto col = bins + size_t( x ) * h;
        const auto x0 = wpos.x + x;
        const auto x1 = x0 + 1;
        int y = 0;
        while( y < h )
        {
            const auto level = Level( col[y] );
            if( level < 0 )
            {
                y++;
                continue;
            }
            auto y1 = y + 1;
            while( y1 < h && Level( col[y1] ) == level ) y1++;
            draw->AddRectFilled( ImVec2( x0, RowToY( y1 ) ), ImVec2( x1, RowToY( y ) ), palette[level] );
            y = y1;
        }
    }

    if( ctx.hover && ImGui::IsMouseHoveringRect( ImVec2( wpos.x, yTop ), ImVec2( wpos.x + w, yBottom ) ) )
    {
        const auto mouse = ImGui::GetMousePos();
        const auto x = std::clamp( int( mouse.x - wpos.x ), 0, w-1 );
        const auto col = bins + size_t( x ) * h;

        uint64_t total = 0;
        int rowMin = -1;
        int rowMax = -1;
        for( int y=0; y<h; y++ )
        {
            if( col[y] == 0 ) continue;
            total += col[y];
            if( rowMin < 0 ) rowMin = y;
            rowMax = y;
        }
        if( total > 0 )
        {
            const auto mv = min + ( yBottom - mouse.y ) / PlotHeight * ( max - min );
            const auto row = std::clamp( int( floor( ( mv - plot.rMin ) / step ) ), 0, h-1 );

            ImGui::BeginTooltip();
            if( sp.skip > 1 )
            {
                TextFocused( "Estimated number of values:", RealToString( total * sp.skip ) );
            }
            else
            {
                TextFocused( "Number of values:", RealToString( total ) );
            }
            TextDisabledUnformatted( "Range:" );
            ImGui::SameLine();
            const auto vmin = RoundToStep( plot.rMin + rowMin * step, step );
            const auto vmax = RoundToStep( plot.rMin + ( rowMax + 1 ) * step, step );
            ImGui::Text( "%s - %s", FormatPlotValue( vmin, plot.format ), FormatPlotValue( vmax, plot.format ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", FormatPlotValue( RoundToStep( vmax - vmin, step ), plot.format ) );
            ImGui::Separator();
            TextFocused( "Values at cursor:", RealToString( uint64_t( col[row] ) * sp.skip ) );
            TextDisabledUnformatted( "Cursor bin:" );
            ImGui::SameLine();
            const auto bmin = RoundToStep( plot.rMin + row * step, step );
            const auto bmax = RoundToStep( plot.rMin + ( row + 1 ) * step, step );
            ImGui::Text( "%s - %s", FormatPlotValue( bmin, plot.format ), FormatPlotValue( bmax, plot.format ) );
            ImGui::EndTooltip();

            draw->AddRect( ImVec2( wpos.x + x - 1, yTop ), ImVec2( wpos.x + x + 2, yBottom ), 0x88FFFFFF );
        }
    }
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
                    auto csAlloc = ev->CsAlloc();
                    if( csAlloc != 0 ) DrawCallstackCalls( csAlloc, 4 );
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
                        auto csFree = ev->csFree.Val();
                        if( csFree != 0 ) DrawCallstackCalls( csFree, 4 );
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
                    if( IsMouseClicked( ImGuiMouseButton_Left ) )
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
