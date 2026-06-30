#include <assert.h>
#include <inttypes.h>

#include "TracyColor.hpp"
#include "TracyEvent.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyVector.hpp"
#include "TracyView.hpp"
#include "tracy_pdqsort.h"
#include "../Fonts.hpp"

namespace tracy
{

constexpr float MinVisSize = 3;

void View::BuildFlameGraph( const Worker& worker, std::vector<FlameGraphItem>& data, const Vector<short_ptr<ZoneEvent>>& zones )
{
    FlameGraphItem* cache;
    int16_t last = 0;

    if( zones.is_magic() )
    {
        auto& vec = *(Vector<ZoneEvent>*)&zones;
        for( auto& v : vec )
        {
            if( !v.IsEndValid() ) break;
            const auto srcloc = v.SrcLoc();

            auto start = v.Start();
            auto end = v.End();

            if ( m_flameGraphInvariant.range.active )
            {
                start = std::clamp(start, m_flameGraphInvariant.range.min, m_flameGraphInvariant.range.max);
                end = std::clamp(end, m_flameGraphInvariant.range.min, m_flameGraphInvariant.range.max);
            }

            const auto duration = end - start;
            if( srcloc == last )
            {
                cache->time += duration;
                if( v.HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v.Child() );
                    BuildFlameGraph( worker, cache->children, children );
                }
            }
            else
            {
                auto it = std::find_if( data.begin(), data.end(), [srcloc]( const auto& v ) { return v.srcloc == srcloc; } );
                if( it == data.end() )
                {
                    data.emplace_back( FlameGraphItem { srcloc, duration } );
                    if( v.HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v.Child() );
                        BuildFlameGraph( worker, data.back().children, children );
                    }
                    cache = &data.back();
                }
                else
                {
                    it->time += duration;
                    if( v.HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v.Child() );
                        BuildFlameGraph( worker, it->children, children );
                    }
                    cache = &*it;
                }
                last = srcloc;
            }
        }
    }
    else
    {
        for( auto& v : zones )
        {
            if( !v->IsEndValid() ) break;
            const auto srcloc = v->SrcLoc();

            auto start = v->Start();
            auto end = v->End();

            if ( m_flameGraphInvariant.range.active )
            {
                start = std::clamp(start, m_flameGraphInvariant.range.min, m_flameGraphInvariant.range.max);
                end = std::clamp(end, m_flameGraphInvariant.range.min, m_flameGraphInvariant.range.max);
            }

            const auto duration = end - start;
            if( srcloc == last )
            {
                cache->time += duration;
                if( v->HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v->Child() );
                    BuildFlameGraph( worker, cache->children, children );
                }
            }
            else
            {
                auto it = std::find_if( data.begin(), data.end(), [srcloc]( const auto& v ) { return v.srcloc == srcloc; } );
                if( it == data.end() )
                {
                    data.emplace_back( FlameGraphItem { srcloc, duration } );
                    if( v->HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v->Child() );
                        BuildFlameGraph( worker, data.back().children, children );
                    }
                    cache = &data.back();
                }
                else
                {
                    it->time += duration;
                    if( v->HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v->Child() );
                        BuildFlameGraph( worker, it->children, children );
                    }
                    cache = &*it;
                }
                last = srcloc;
            }
        }
    }
}

void View::BuildFlameGraph( const Worker& worker, std::vector<FlameGraphItem>& data, const Vector<short_ptr<ZoneEvent>>& zones, const ContextSwitch* ctx )
{
    assert( ctx );
    FlameGraphItem* cache;
    int16_t last = 0;

    if( zones.is_magic() )
    {
        auto& vec = *(Vector<ZoneEvent>*)&zones;
        for( auto& v : vec )
        {
            if( !v.IsEndValid() ) break;
            const auto srcloc = v.SrcLoc();
            int64_t duration;
            if ( m_flameRange.active )
            {
                if( !GetZoneRunningTime( ctx, v, m_flameGraphInvariant.range, duration ) ) continue;
            }
            else
            {
                if( !GetZoneRunningTime( ctx, v, duration ) ) break;
            }

            if( srcloc == last )
            {
                cache->time += duration;
                if( v.HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v.Child() );
                    BuildFlameGraph( worker, cache->children, children, ctx );
                }
            }
            else
            {
                auto it = std::find_if( data.begin(), data.end(), [srcloc]( const auto& v ) { return v.srcloc == srcloc; } );
                if( it == data.end() )
                {
                    data.emplace_back( FlameGraphItem { srcloc, duration } );
                    if( v.HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v.Child() );
                        BuildFlameGraph( worker, data.back().children, children, ctx );
                    }
                    cache = &data.back();
                }
                else
                {
                    it->time += duration;
                    if( v.HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v.Child() );
                        BuildFlameGraph( worker, it->children, children, ctx );
                    }
                    cache = &*it;
                }
                last = srcloc;
            }
        }
    }
    else
    {
        for( auto& v : zones )
        {
            if( !v->IsEndValid() ) break;
            const auto srcloc = v->SrcLoc();
            int64_t duration;
            if ( m_flameRange.active )
            {
                if( !GetZoneRunningTime( ctx, *v, m_flameGraphInvariant.range, duration ) ) continue;
            }
            else
            {
                if( !GetZoneRunningTime( ctx, *v, duration ) ) break;
            }

            if( srcloc == last )
            {
                cache->time += duration;
                if( v->HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v->Child() );
                    BuildFlameGraph( worker, cache->children, children, ctx );
                }
            }
            else
            {
                auto it = std::find_if( data.begin(), data.end(), [srcloc]( const auto& v ) { return v.srcloc == srcloc; } );
                if( it == data.end() )
                {
                    data.emplace_back( FlameGraphItem { srcloc, duration } );
                    if( v->HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v->Child() );
                        BuildFlameGraph( worker, data.back().children, children, ctx );
                    }
                    cache = &data.back();
                }
                else
                {
                    it->time += duration;
                    if( v->HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v->Child() );
                        BuildFlameGraph( worker, it->children, children, ctx );
                    }
                    cache = &*it;
                }
                last = srcloc;
            }
        }
    }
}

void View::BuildFlameGraph( const Worker& worker, std::vector<FlameGraphItem>& data, const Vector<SampleData>& samples, unordered_flat_map<uint32_t, bool>& externalCache, uint32_t& lastImage, uint32_t& lastSource )
{
    struct FrameCache
    {
        uint64_t symaddr;
        StringIdx name;
        bool external;
    };

    std::vector<FrameCache> cache;

    for( auto& v : samples )
    {
        if ( m_flameGraphInvariant.range.active )
        {
            if ( v.time.Val() < m_flameGraphInvariant.range.min ||
                 v.time.Val() > m_flameGraphInvariant.range.max )
            {
                continue;
            }
        }

        cache.clear();

        const auto cs = v.callstack.Val();
        const auto& callstack = worker.GetCallstack( cs );
        const auto csz = callstack.size();
        if( m_flameExternal )
        {
            for( size_t i=csz; i>0; i-- )
            {
                auto frameData = worker.GetCallstackFrame( callstack[i-1] );
                if( frameData )
                {
                    for( uint8_t j=frameData->size; j>0; j-- )
                    {
                        const auto frame = frameData->data[j-1];
                        const auto symaddr = frame.symAddr;
                        if( symaddr != 0 )
                        {
                            cache.emplace_back( FrameCache { symaddr, frame.name } );
                        }
                    }
                }
            }
        }
        else if( !m_flameExternalTail )
        {
            for( size_t i=csz; i>0; i-- )
            {
                auto frameData = worker.GetCallstackFrame( callstack[i-1] );
                if( frameData )
                {
                    if( !frameData->imageName.Active() || !m_worker.IsImageExternal( frameData->imageName, externalCache, lastImage ) )
                    {
                        for( uint8_t j=frameData->size; j>0; j-- )
                        {
                            const auto frame = frameData->data[j-1];
                            const auto symaddr = frame.symAddr;
                            if( symaddr != 0 && !m_worker.IsSourceExternal( frame.file, externalCache, lastSource ) )
                            {
                                cache.emplace_back( FrameCache { symaddr, frame.name } );
                            }
                        }
                    }
                }
            }
        }
        else
        {
            for( size_t i=csz; i>0; i-- )
            {
                auto frameData = worker.GetCallstackFrame( callstack[i-1] );
                if( frameData )
                {
                    bool imageExternal = frameData->imageName.Active() && m_worker.IsImageExternal( frameData->imageName, externalCache, lastImage );
                    for( uint8_t j=frameData->size; j>0; j-- )
                    {
                        const auto frame = frameData->data[j-1];
                        const auto symaddr = frame.symAddr;
                        if( symaddr != 0 )
                        {
                            bool external = imageExternal || m_worker.IsSourceExternal( frame.file, externalCache, lastSource );
                            cache.emplace_back( FrameCache { symaddr, frame.name, external } );
                        }
                    }
                }
            }

            bool tail = true;
            for( size_t i=cache.size(); i>0; i-- )
            {
                const auto idx = i-1;
                if( !cache[idx].external )
                {
                    tail = false;
                }
                else if( !tail )
                {
                    cache.erase( cache.begin() + idx );
                }
            }
        }

        const auto period = worker.GetSamplingPeriod();
        auto vec = &data;
        for( auto& v : cache )
        {
            auto it = std::find_if( vec->begin(), vec->end(), [symaddr = v.symaddr]( const auto& v ) { return v.srcloc == symaddr; } );
            if( it == vec->end() )
            {
                vec->emplace_back( FlameGraphItem { (int64_t)v.symaddr, period, v.name } );
                vec = &vec->back().children;
            }
            else
            {
                it->time += period;
                vec = &it->children;
            }
        }
    }
}

static void SortFlameGraph( std::vector<FlameGraphItem>& data )
{
    pdqsort_branchless( data.begin(), data.end(), []( const FlameGraphItem& lhs, const FlameGraphItem& rhs ) { return lhs.time > rhs.time; } );
    for( auto& v : data ) SortFlameGraph( v.children );
}

struct FlameGraphContext
{
    ImDrawList* draw;
    ImVec2 wpos;
    ImVec2 dpos;
    float w;
    float ty;
    float ostep;
    double pxns;
    double nspx;
    int64_t vStart;
    int64_t vEnd;
    float yMin;
    float yMax;
};

void View::DrawFlameGraphLevel( const std::vector<FlameGraphItem>& data, FlameGraphContext& ctx, int depth, bool samples )
{
    const auto vStart = ctx.vStart;
    const auto vEnd = ctx.vEnd;
    const auto nspx = ctx.nspx;
    const auto pxns = ctx.pxns;
    const auto draw = ctx.draw;
    const auto ostep = ctx.ostep;
    const auto& wpos = ctx.wpos;

    const auto y0 = wpos.y + depth * ostep;
    if( y0 > ctx.yMax ) return;

    const auto y1 = y0 + ctx.ty;
    const auto visibleY = y1 >= ctx.yMin;

    const auto MinVisNs = int64_t( round( GetScale() * MinVisSize * nspx ) );

    auto it = std::lower_bound( data.begin(), data.end(), vStart, [] ( const auto& l, const auto& r ) { return l.begin + l.time < r; } );
    if( it == data.end() ) return;

    const auto zitend = std::lower_bound( it, data.end(), vEnd, [] ( const auto& l, const auto& r ) { return l.begin < r; } );
    if( it == zitend ) return;

    while( it < zitend )
    {
        const auto end = it->begin + it->time;
        const auto zsz = it->time;
        if( zsz < MinVisNs )
        {
            auto nextTime = end + MinVisNs;
            auto next = it + 1;
            for(;;)
            {
                next = std::lower_bound( next, zitend, nextTime, [] ( const auto& l, const auto& r ) { return l.begin + l.time < r; } );
                if( next == zitend ) break;
                if( next->time >= MinVisNs ) break;
                nextTime = next->begin + next->time + MinVisNs;
            }
            const auto px0 = ( it->begin - vStart ) * pxns;
            const auto px1 = ( (next-1)->begin + (next-1)->time - vStart ) * pxns;
            if( visibleY )
            {
                const auto drawX0 = std::max( px0, -10.0 );
                const auto drawX1 = std::min( std::max( px1, px0 + MinVisSize ), double( ctx.w + 10 ) );
                draw->AddRectFilled( ImVec2( wpos.x + drawX0, y0 ), ImVec2( wpos.x + drawX1, y0 + ostep ), 0xFF666666 );
                DrawZigZag( draw, ImVec2( wpos.x, y0 + 0.5f * ostep ), drawX0, drawX1, ctx.ty / 4, 0xFF444444 );
            }
            it = next;
        }
        else
        {
            DrawFlameGraphItem( *it, ctx, depth, samples );
            ++it;
        }
    }
}

void View::DrawFlameGraphItem( const FlameGraphItem& item, FlameGraphContext& ctx, int depth, bool samples )
{
    const auto x0 = ctx.dpos.x + ( item.begin - ctx.vStart ) * ctx.pxns;
    const auto x1 = x0 + item.time * ctx.pxns;
    const auto y0 = ctx.dpos.y + depth * ctx.ostep;
    const auto y1 = y0 + ctx.ty;

    if( y0 > ctx.yMax ) return;
    if( y1 < ctx.yMin )
    {
        DrawFlameGraphLevel( item.children, ctx, depth+1, samples );
        return;
    }

    const SourceLocation* srcloc;
    uint32_t color;
    const char* name;
    const char* normalized;
    const char* slName;

    uint32_t textColor = 0xFFFFFFFF;

    if( !samples )
    {
        srcloc = &m_worker.GetSourceLocation( item.srcloc );
        color = GetSrcLocColor( *srcloc, depth );
        name = slName = m_worker.GetString( srcloc->name.active ? srcloc->name : srcloc->function );
    }
    else
    {
        name = m_worker.GetString( item.name );
        const auto symAddr = (uint64_t)item.srcloc;
        auto sym = m_worker.GetSymbolData( symAddr );
        if( sym )
        {
            auto namehash = charutil::hash( name );
            if( namehash == 0 ) namehash++;
            color = GetHsvColor( namehash, depth );
            if( sym->isInline )
            {
                color = DarkenColorHalf( color );
            }
        }
        else
        {
            color = 0xFF888888;
        }
        if( symAddr >> 63 != 0 )
        {
            textColor = 0xFF8888FF;
        }
    }

    const auto hiColor = HighlightColor( color );
    const auto darkColor = DarkenColor( color );
    const auto drawX0 = std::max<double>( x0, ctx.wpos.x - 10.0 );
    const auto drawX1 = std::min<double>( std::max( x1, x0 + MinVisSize ), ctx.wpos.x + ctx.w + 10.0 );

    const auto zsz = x1 - x0;

    auto tsz = ImGui::CalcTextSize( name );
    if( m_vd.shortenName == ShortenName::Never )
    {
        normalized = name;
    }
    else if( samples )
    {
        normalized = ShortenZoneName( ShortenName::OnlyNormalize, name );
        tsz = ImGui::CalcTextSize( normalized );
        if( tsz.x > zsz && ( m_vd.shortenName == ShortenName::NoSpace || m_vd.shortenName == ShortenName::NoSpaceAndNormalize ) )
        {
            normalized = ShortenZoneName( m_vd.shortenName, normalized, tsz, zsz );
        }
    }
    else if( m_vd.shortenName == ShortenName::Always || ( ( m_vd.shortenName == ShortenName::NoSpace || m_vd.shortenName == ShortenName::NoSpaceAndNormalize ) && tsz.x > zsz ) )
    {
        normalized = ShortenZoneName( m_vd.shortenName, name, tsz, zsz );
    }
    else
    {
        normalized = name;
    }

    const bool hover = ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect( ImVec2( drawX0, y0 ), ImVec2( drawX1, y1 ) );

    ctx.draw->AddRectFilled( ImVec2( drawX0, y0 ), ImVec2( drawX1, y1 ), color );
    if( hover )
    {
        ctx.draw->AddRect( ImVec2( drawX0 - 0.5f, y0 - 0.5f ), ImVec2( drawX1 - 0.5f, y1 - 0.5f ), 0xFFEEEEEE );
    }
    else
    {
        DrawLine( ctx.draw, ImVec2( drawX0, y1 ), ImVec2( drawX0, y0 ), ImVec2( drawX1-1, y0 ), hiColor );
        DrawLine( ctx.draw, ImVec2( drawX0, y1 ), ImVec2( drawX1-1, y1), ImVec2( drawX1-1, y0 ), darkColor );
    }

    const auto tx0 = std::max<double>( x0, ctx.wpos.x );
    const auto tx1 = std::min<double>( x1, ctx.wpos.x + ctx.w );
    if( tx1 > tx0 && tsz.x < zsz )
    {
        const auto x = ( x1 + x0 - tsz.x ) * 0.5;
        if( x < tx0 || x > tx1 - tsz.x )
        {
            ImGui::PushClipRect( ImVec2( tx0, y0 ), ImVec2( tx1, y1 ), true );
            DrawTextContrast( ctx.draw, ImVec2( std::max( tx0, std::min( tx1 - tsz.x, x ) ), y0 ), textColor, normalized );
            ImGui::PopClipRect();
        }
        else
        {
            DrawTextContrast( ctx.draw, ImVec2( x, y0 ), textColor, normalized );
        }
    }
    else if( tx1 > tx0 )
    {
        ImGui::PushClipRect( ImVec2( tx0, y0 ), ImVec2( tx1, y1 ), true );
        DrawTextContrast( ctx.draw, ImVec2( tx0, y0 ), textColor, normalized );
        ImGui::PopClipRect();
    }

    if( hover )
    {
        uint64_t self = item.time;
        for( auto& v : item.children ) self -= v.time;

        ImGui::BeginTooltip();
        if( samples )
        {
            const auto symAddr = (uint64_t)item.srcloc;
            auto sym = m_worker.GetSymbolData( symAddr );
            if( sym )
            {
                TextFocused( "Name:", normalized );
                if( sym->isInline )
                {
                    ImGui::SameLine();
                    TextDisabledUnformatted( "[inline]" );
                }
                const bool isKernel = symAddr >> 63 != 0;
                if( isKernel )
                {
                    ImGui::SameLine();
                    TextDisabledUnformatted( ICON_FA_HAT_WIZARD " kernel" );
                }
                ImGui::SameLine();
                ImGui::PushFont( g_fonts.normal, FontSmall );
                ImGui::AlignTextToFramePadding();
                ImGui::TextDisabled( "0x%" PRIx64, symAddr );
                ImGui::PopFont();
                if( normalized != name && strcmp( normalized, name ) != 0 )
                {
                    ImGui::PushFont( g_fonts.normal, FontSmall );
                    TextDisabledUnformatted( name );
                    ImGui::PopFont();
                }
                ImGui::Separator();
                const char* file;
                uint32_t line;
                if( sym->isInline )
                {
                    file = m_worker.GetString( sym->callFile );
                    line = sym->callLine;
                }
                else
                {
                    file = m_worker.GetString( sym->file );
                    line = sym->line;
                }
                if( file[0] != '[' )
                {
                    ImGui::TextDisabled( "Location:" );
                    ImGui::SameLine();
                    ImGui::TextUnformatted( LocationToString( file, line ) );
                }
                TextFocused( "Image:", m_worker.GetString( sym->imageName ) );
                ImGui::Separator();
                TextFocused( "Execution time:", TimeToString( item.time ) );
                if( !item.children.empty() )
                {
                    TextFocused( "Self time:", TimeToString( self ) );
                    char buf[64];
                    PrintStringPercent( buf, 100.f * self / item.time );
                    ImGui::SameLine();
                    TextDisabledUnformatted( buf );
                }

                if( IsMouseClicked( 0 ) )
                {
                    ViewDispatch( file, line, symAddr );
                }
            }
            ImGui::EndTooltip();
        }
        else
        {
            if( srcloc->name.active )
            {
                ImGui::TextUnformatted( m_worker.GetString( srcloc->name ) );
            }
            ImGui::TextUnformatted( m_worker.GetString( srcloc->function ) );
            ImGui::Separator();
            SmallColorBox( GetSrcLocColor( *srcloc, 0 ) );
            ImGui::SameLine();
            ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc->file ), srcloc->line ) );
            ImGui::Separator();
            TextFocused( "Execution time:", TimeToString( item.time ) );
            if( !item.children.empty() )
            {
                TextFocused( "Self time:", TimeToString( self ) );
                char buf[64];
                PrintStringPercent( buf, 100.f * self / item.time );
                ImGui::SameLine();
                TextDisabledUnformatted( buf );
            }
            ImGui::EndTooltip();

            if( IsMouseClicked( 0 ) )
            {
                m_findZone.ShowZone( item.srcloc, slName );
            }
        }
    }

    DrawFlameGraphLevel( item.children, ctx, depth+1, samples );
}

void View::DrawFlameGraphHeader( int64_t vStart, int64_t vEnd )
{
    assert( vStart < vEnd );

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto w = ImGui::GetContentRegionAvail().x;// - ImGui::GetStyle().ScrollbarSize;
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetTextLineHeight();
    const auto ty025 = round( ty * 0.25f );
    const auto ty0375 = round( ty * 0.375f );
    const auto ty05 = round( ty * 0.5f );

    if( w <= 0 )
    {
        ImGui::Dummy( ImVec2( 0, ty * 1.5f ) );
        return;
    }

    const auto timespan = vEnd - vStart;
    const auto pxns = w / double( timespan );
    const auto nspx = 1.0 / pxns;
    const auto scale = std::max( 0.0, round( log10( nspx ) + 2 ) );
    const auto step = pow( 10, scale );

    ImGui::InvisibleButton( "##flameHeader", ImVec2( w, ty * 1.5f ) );
    TooltipIfHovered( TimeToStringExact( ( ImGui::GetIO().MousePos.x - wpos.x ) * nspx ) );

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
            auto txt = "0";
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

static bool ApplyFlameGraphPan( int64_t& start, int64_t& end, double& pan, double delta )
{
    pan += delta;
    const auto d = int64_t( pan );
    if( d == 0 ) return false;

    start += d;
    end += d;
    pan -= d;
    return true;
}

static bool DrawFlameGraphHorizontalPosition( int64_t& vStart, int64_t& vEnd, double& pan, int64_t totalSpan )
{
    assert( vStart < vEnd );
    assert( totalSpan > 0 );

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto w = ImGui::GetContentRegionAvail().x;
    const auto scale = GetScale();
    const auto h = std::max( 8.f * scale, 8.f );

    if( w <= 0 )
    {
        ImGui::Dummy( ImVec2( 0, h ) );
        return false;
    }

    ImGui::InvisibleButton( "##flameHorizontalPosition", ImVec2( w, h ) );
    const auto hover = ImGui::IsItemHovered();
    const auto active = ImGui::IsItemActive();
    auto draw = ImGui::GetWindowDrawList();

    const auto fullSpan = float( totalSpan );
    const auto x0 = wpos.x + w * ( float( vStart ) / fullSpan );
    const auto x1 = wpos.x + w * ( float( vEnd ) / fullSpan );
    auto thumbX0 = std::max( wpos.x, std::min( wpos.x + w, x0 ) );
    auto thumbX1 = std::max( thumbX0, std::min( wpos.x + w, x1 ) );
    const auto minThumbWidth = std::max( 9.f * scale, 9.f );
    if( thumbX1 - thumbX0 < minThumbWidth )
    {
        const auto center = ( thumbX0 + thumbX1 ) * 0.5f;
        thumbX0 = center - ( minThumbWidth * 0.5f );
        thumbX1 = center + ( minThumbWidth * 0.5f );
        if( thumbX0 < wpos.x )
        {
            thumbX0 = wpos.x;
            thumbX1 = thumbX0 + minThumbWidth;
        }
        else if( thumbX1 > wpos.x + w )
        {
            thumbX1 = wpos.x + w;
            thumbX0 = thumbX1 - minThumbWidth;
        }
    }
    const auto y0 = wpos.y + floor( h * 0.25f );
    const auto y1 = wpos.y + ceil( h * 0.75f );

    draw->AddRectFilled( ImVec2( wpos.x, y0 ), ImVec2( wpos.x + w, y1 ), 0x33888888 );
    draw->AddRectFilled( ImVec2( thumbX0, y0 ), ImVec2( thumbX1, y1 ), active ? 0xCCFFFFFF : hover ? 0xAAFFFFFF : 0x66FFFFFF );

    if( hover )
    {
        ImGui::BeginTooltip();
        TextFocused( "View span:", TimeToString( vEnd - vStart ) );
        ImGui::EndTooltip();
    }

    if( active && ImGui::IsMouseDragging( 0 ) )
    {
        const auto delta = ImGui::GetIO().MouseDelta.x;
        ApplyFlameGraphPan( vStart, vEnd, pan, delta * totalSpan / w );
        return delta != 0;
    }

    return false;
}

static void MergeFlameGraph( std::vector<FlameGraphItem>& dst, std::vector<FlameGraphItem>&& src )
{
    for( auto& v : src )
    {
        auto it = std::find_if( dst.begin(), dst.end(), [&v]( const auto& vv ) { return vv.srcloc == v.srcloc; } );
        if( it == dst.end() )
        {
            dst.emplace_back( std::move( v ) );
        }
        else
        {
            it->time += v.time;
            MergeFlameGraph( it->children, std::move( v.children ) );
        }
    }
}

static void FixupTime( std::vector<FlameGraphItem>& data, uint64_t t = 0 )
{
    for( auto& v : data )
    {
        v.begin = t;
        if( !v.children.empty() ) FixupTime( v.children, t );
        t += v.time;
    }
}

static int64_t GetFlameGraphTime( const std::vector<FlameGraphItem>& data )
{
    int64_t time = 0;
    for( const auto& v : data ) time += v.time;
    return time;
}

static int GetFlameGraphDepth( const std::vector<FlameGraphItem>& data, int64_t minVisNs )
{
    int maxDepth = 1;
    for( const auto& v : data )
    {
        if( v.time >= minVisNs && !v.children.empty() )
        {
            maxDepth = std::max( maxDepth, 1 + GetFlameGraphDepth( v.children, minVisNs ) );
        }
    }
    return maxDepth;
}

static void ClampFlameGraphViewport( int64_t& start, int64_t& end, int64_t totalSpan )
{
    assert( totalSpan > 0 );

    if( end < start ) std::swap( start, end );

    const int64_t minSpan = 5;
    auto span = end - start;
    if( span < minSpan )
    {
        span = minSpan;
        const auto center = ( start + end ) / 2;
        start = center - span / 2;
        end = start + span;
    }

    if( span >= totalSpan )
    {
        start = 0;
        end = totalSpan;
        return;
    }

    if( start < 0 )
    {
        start = 0;
        end = span;
    }
    else if( end > totalSpan )
    {
        end = totalSpan;
        start = end - span;
    }

    assert( start >= 0 );
    assert( end <= totalSpan );
    assert( end > start );
}


void View::DrawFlameGraph()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Flame graph", &m_showFlameGraph, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
    if( ImGui::RadioButton( ICON_FA_SYRINGE " Instrumentation", &m_flameMode, 0 ) )
    {
        m_flameGraphInvariant.Reset();
        m_flameGraphViewStart = 0;
        m_flameGraphViewEnd = 0;
        m_flameGraphPan = 0;
    }

    if( m_worker.AreCallstackSamplesReady() && m_worker.GetCallstackSampleCount() > 0 )
    {
        ImGui::SameLine();
        if( ImGui::RadioButton( ICON_FA_EYE_DROPPER " Sampling", &m_flameMode, 1 ) )
        {
            m_flameGraphInvariant.Reset();
            m_flameGraphViewStart = 0;
            m_flameGraphViewEnd = 0;
            m_flameGraphPan = 0;
        }
    }

    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();

    if( ImGui::Checkbox( ICON_FA_ARROW_UP_WIDE_SHORT " Sort by time", &m_flameSort ) )
    {
        m_flameGraphInvariant.Reset();
        m_flameGraphViewStart = 0;
        m_flameGraphViewEnd = 0;
        m_flameGraphPan = 0;
    }

    if( m_flameMode == 0 )
    {
        if( m_worker.HasContextSwitches() )
        {
            ImGui::SameLine();
            if( ImGui::Checkbox( "Running time", &m_flameRunningTime ) )
            {
                m_flameGraphInvariant.Reset();
                m_flameGraphViewStart = 0;
                m_flameGraphViewEnd = 0;
                m_flameGraphPan = 0;
            }
        }
        else
        {
            assert( !m_flameRunningTime );
        }
    }
    else
    {
        ImGui::SameLine();
        ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
        ImGui::SameLine();
        ImGui::Text( ICON_FA_SHIELD_HALVED "External" );
        ImGui::SameLine();
        if( ImGui::Checkbox( "Frames", &m_flameExternal ) )
        {
            m_flameGraphInvariant.Reset();
            m_flameGraphViewStart = 0;
            m_flameGraphViewEnd = 0;
            m_flameGraphPan = 0;
        }
        ImGui::SameLine();
        if( m_flameExternal ) ImGui::BeginDisabled();
        if( ImGui::Checkbox( "Tails", &m_flameExternalTail ) )
        {
            m_flameGraphInvariant.Reset();
            m_flameGraphViewStart = 0;
            m_flameGraphViewEnd = 0;
            m_flameGraphPan = 0;
        }
        if( m_flameExternal ) ImGui::EndDisabled();
    }

    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();

    if( ImGui::Checkbox( "Limit range", &m_flameRange.active ) )
    {
        if( m_flameRange.active && m_flameRange.min == 0 && m_flameRange.max == 0 )
        {
            m_flameRange.min = m_vd.zvStart;
            m_flameRange.max = m_vd.zvEnd;
        }

        m_flameGraphInvariant.Reset();
        m_flameGraphViewStart = 0;
        m_flameGraphViewEnd = 0;
        m_flameGraphPan = 0;
    }
    if( m_flameRange.active )
    {
        ImGui::SameLine();
        TextColoredUnformatted( 0xFF00FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
        ImGui::SameLine();
        ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
    }

    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();

    if( ImGui::Button( "Reset view" ) )
    {
        m_flameGraphViewStart = 0;
        m_flameGraphViewEnd = 0;
        m_flameGraphPan = 0;
    }

    UpdateThreadOrder();
    const auto& td = m_threadOrder;
    auto expand = ImGui::TreeNode( ICON_FA_SHUFFLE " Visible threads:" );
    ImGui::SameLine();
    size_t visibleThreads = 0;
    size_t tsz = 0;
    for( const auto& t : td )
    {
        if( FlameGraphThread( t->id ) ) visibleThreads++;
        tsz++;
    }
    if( visibleThreads == tsz )
    {
        ImGui::TextDisabled( "(%zu)", tsz );
    }
    else
    {
        ImGui::TextDisabled( "(%zu/%zu)", visibleThreads, tsz );
    }
    if( expand )
    {
        ImGui::SameLine();
        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& t : td )
            {
                FlameGraphThread( t->id ) = true;
            }
            m_flameGraphInvariant.Reset();
            m_flameGraphViewStart = 0;
            m_flameGraphViewEnd = 0;
            m_flameGraphPan = 0;
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : td )
            {
                FlameGraphThread( t->id ) = false;
            }
            m_flameGraphInvariant.Reset();
            m_flameGraphViewStart = 0;
            m_flameGraphViewEnd = 0;
            m_flameGraphPan = 0;
        }

        const auto& style = ImGui::GetStyle();
        float probe = 0;
        for( auto& t : td )
        {
            float w = ImGui::GetFrameHeight() * 2 + ImGui::CalcTextSize( m_worker.GetThreadName( t->id ) ).x + style.ItemSpacing.x * 2;
            if( t->isFiber ) w += style.ItemSpacing.x + ImGui::CalcTextSize( "Fiber" ).x;
            probe = std::max( probe, w );
        }
        const auto MinWidth = std::max( 150 * GetScale(), probe );
        const int cols = std::max( 1, int( ImGui::GetContentRegionAvail().x / MinWidth ) );

        const auto rows = ( tsz + cols - 1 ) / cols;
        const auto rowsVisible = std::min<float>( rows, 7.5f );
        const auto rowsHeight = ImGui::GetTextLineHeightWithSpacing() * rowsVisible;
        ImGui::BeginChild( "###flamegraphthreadrows", ImVec2( -1, rowsHeight ) );

        int idx = 0;
        ImGui::BeginTable( "##flamegraphthreadcols", cols, ImGuiTableFlags_NoSavedSettings );
        for( const auto& t : td )
        {
            ImGui::TableNextColumn();
            ImGui::PushID( idx++ );
            const auto threadColor = GetThreadColor( t->id, 0 );
            SmallColorBox( threadColor );
            ImGui::SameLine();
            if( SmallCheckbox( m_worker.GetThreadName( t->id ), &FlameGraphThread( t->id ) ) )
            {
                m_flameGraphInvariant.Reset();
                m_flameGraphViewStart = 0;
                m_flameGraphViewEnd = 0;
                m_flameGraphPan = 0;
            }
            ImGui::PopID();
            if( t->isFiber )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
        }
        ImGui::EndTable();
        ImGui::EndChild();
        ImGui::TreePop();
    }

    ImGui::Separator();
    ImGui::PopStyleVar();

    bool flameDataRebuilt = false;
    const auto oldZsz = GetFlameGraphTime( m_flameGraphData );
    const auto flameRangeChanged = m_flameGraphInvariant.range != m_flameRange;
    if( m_flameMode == 0 && ( m_flameGraphInvariant.count != m_worker.GetZoneCount() || m_flameGraphInvariant.lastTime != m_worker.GetLastTime() ) ||
        m_flameMode == 1 && ( m_flameGraphInvariant.count != m_worker.GetCallstackSampleCount() ) ||
        flameRangeChanged )
    {
        if( flameRangeChanged )
        {
            m_flameGraphViewStart = 0;
            m_flameGraphViewEnd = 0;
            m_flameGraphPan = 0;
        }
        m_flameGraphInvariant.range = m_flameRange;

        size_t sz = 0;
        for( auto& thread : td ) if( FlameGraphThread( thread->id ) ) sz++;

        std::vector<std::vector<FlameGraphItem>> threadData;
        threadData.resize( sz );

        size_t idx = 0;
        if( m_flameMode == 0 )
        {
            for( auto& thread : td )
            {
                if( FlameGraphThread( thread->id ) )
                {
                    if( m_flameRunningTime )
                    {
                        const auto ctx = m_worker.GetContextSwitchData( thread->id );
                        if( ctx )
                        {
                            m_td.Queue( [this, idx, ctx, thread, &threadData] {
                                BuildFlameGraph( m_worker, threadData[idx], thread->timeline, ctx );
                            } );
                        }
                    }
                    else
                    {
                        m_td.Queue( [this, idx, thread, &threadData] {
                            BuildFlameGraph( m_worker, threadData[idx], thread->timeline );
                        } );
                    }
                    idx++;
                }
            }

            m_flameGraphInvariant.count = m_worker.GetZoneCount();
            m_flameGraphInvariant.lastTime = m_worker.GetLastTime();
        }
        else
        {
            for( auto& thread : td )
            {
                if( FlameGraphThread( thread->id ) )
                {
                    m_td.Queue( [this, idx, thread, &threadData] {
                        unordered_flat_map<uint32_t, bool> externalCache;
                        uint32_t lastImage = 0;
                        uint32_t lastSource = 0;
                        BuildFlameGraph( m_worker, threadData[idx], thread->samples, externalCache, lastImage, lastSource );
                    } );
                    idx++;
                }
            }

            m_flameGraphInvariant.count = m_worker.GetCallstackSampleCount();
        }
        m_td.Sync();

        m_flameGraphData.clear();
        if( !threadData.empty() )
        {
            std::swap( m_flameGraphData, threadData[0] );
            for( size_t i=1; i<threadData.size(); i++ )
            {
                MergeFlameGraph( m_flameGraphData, std::move( threadData[i] ) );
            }
        }

        if( m_flameSort ) SortFlameGraph( m_flameGraphData );
        FixupTime( m_flameGraphData );
        flameDataRebuilt = true;
    }

    const auto zsz = GetFlameGraphTime( m_flameGraphData );

    if( m_flameGraphData.empty() || zsz <= 0 )
    {
        m_flameGraphZoomAnim.active = false;

        const auto region = ImGui::GetContentRegionAvail();
        ImGui::PushFont( g_fonts.normal, FontBig );
        ImGui::Dummy( ImVec2( 0, ( region.y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
        TextCentered( ICON_FA_CAT );
        TextCentered( "No data available to display" );
        ImGui::PopFont();
    }
    else
    {
        const auto viewStart = m_flameGraphZoomAnim.active ? m_flameGraphZoomAnim.start1 : m_flameGraphViewStart;
        const auto viewEnd = m_flameGraphZoomAnim.active ? m_flameGraphZoomAnim.end1 : m_flameGraphViewEnd;
        if( m_flameGraphViewEnd <= m_flameGraphViewStart || m_flameGraphViewStart < 0 )
        {
            m_flameGraphViewStart = 0;
            m_flameGraphViewEnd = zsz;
            m_flameGraphPan = 0;
            m_flameGraphZoomAnim.active = false;
        }
        else if( flameDataRebuilt && oldZsz > 0 && viewStart == 0 && viewEnd == oldZsz )
        {
            m_flameGraphViewEnd = zsz;
            m_flameGraphPan = 0;
            m_flameGraphZoomAnim.active = false;
        }
        else if( flameDataRebuilt && m_flameGraphZoomAnim.active )
        {
            ClampFlameGraphViewport( m_flameGraphZoomAnim.start1, m_flameGraphZoomAnim.end1, zsz );
        }

        UpdateZoomAnimation( m_flameGraphZoomAnim, m_flameGraphViewStart, m_flameGraphViewEnd, ImGui::GetIO().DeltaTime );
        ClampFlameGraphViewport( m_flameGraphViewStart, m_flameGraphViewEnd, zsz );

        DrawFlameGraphHeader( m_flameGraphViewStart, m_flameGraphViewEnd );
        if( DrawFlameGraphHorizontalPosition( m_flameGraphViewStart, m_flameGraphViewEnd, m_flameGraphPan, zsz ) )
        {
            m_flameGraphZoomAnim.active = false;
            ClampFlameGraphViewport( m_flameGraphViewStart, m_flameGraphViewEnd, zsz );
        }

        ImGui::BeginChild( "##flameGraphBody", ImVec2( 0, 0 ), false, ImGuiWindowFlags_NoScrollWithMouse );
        const auto region = ImGui::GetContentRegionAvail();
        const auto wpos = ImGui::GetCursorScreenPos();
        const auto w = region.x;
        if( w <= 0 )
        {
            ImGui::ItemSize( region );
            ImGui::EndChild();
            ImGui::End();
            return;
        }
        const auto timespan = m_flameGraphViewEnd - m_flameGraphViewStart;
        const auto nspx = double( timespan ) / w;
        auto& io = ImGui::GetIO();
        auto draw = ImGui::GetWindowDrawList();
        const auto clipMin = draw->GetClipRectMin();
        const auto clipMax = draw->GetClipRectMax();
        const auto hover = ImGui::IsWindowHovered( ImGuiHoveredFlags_AllowWhenBlockedByActiveItem ) &&
            ImGui::IsMouseHoveringRect( ImVec2( wpos.x, clipMin.y ), ImVec2( wpos.x + w, clipMax.y ), false );

        const bool wheel_scroll = fabs( io.MouseWheelH ) > fabs( io.MouseWheel );
        if( hover && ( IsMouseDragging( 1 ) || wheel_scroll ) )
        {
            const auto delta = GetMouseDragDelta( 1 );
            const auto hwheel_delta = io.MouseWheelH * 50.f * m_horizontalScrollMultiplier;
            if( delta.x != 0 || hwheel_delta != 0 )
            {
                m_flameGraphZoomAnim.active = false;
                const auto changed = ApplyFlameGraphPan( m_flameGraphViewStart, m_flameGraphViewEnd, m_flameGraphPan, -( delta.x + hwheel_delta ) * nspx );
                io.MouseClickedPos[1].x = io.MousePos.x;
                if( changed )
                {
                    ClampFlameGraphViewport( m_flameGraphViewStart, m_flameGraphViewEnd, zsz );
                }
            }

            if( delta.y != 0 )
            {
                ImGui::SetScrollY( std::clamp( ImGui::GetScrollY() - delta.y, 0.0f, ImGui::GetScrollMaxY() ) );
                io.MouseClickedPos[1].y = io.MousePos.y;
            }
        }

        const bool wheel_zoom = fabs( io.MouseWheel ) > fabs( io.MouseWheelH );
        if( hover && wheel_zoom )
        {
            m_flameGraphPan = 0;
            const auto wheel = io.MouseWheel;
            const auto mouse = io.MousePos.x - wpos.x;
            const auto p = mouse / w;
            int64_t vStart, vEnd;
            if( m_flameGraphZoomAnim.active )
            {
                vStart = m_flameGraphZoomAnim.start1;
                vEnd = m_flameGraphZoomAnim.end1;
            }
            else
            {
                vStart = m_flameGraphViewStart;
                vEnd = m_flameGraphViewEnd;
            }
            const auto zoomSpan = vEnd - vStart;
            const auto p1 = zoomSpan * p;
            const auto p2 = zoomSpan - p1;
            double mod = 0.25;
            if( io.KeyCtrl ) mod = 0.05;
            else if( io.KeyShift ) mod = 0.5;
            mod *= m_verticalScrollMultiplier;
#ifndef __EMSCRIPTEN__
            mod *= fabs( wheel );
#endif

            if( wheel > 0 )
            {
                vStart += int64_t( p1 * mod );
                vEnd -= int64_t( p2 * mod );
            }
            else
            {
                vStart -= std::max<int64_t>( 1, int64_t( p1 * mod ) );
                vEnd += std::max<int64_t>( 1, int64_t( p2 * mod ) );
            }
            ClampFlameGraphViewport( vStart, vEnd, zsz );
            m_flameGraphZoomAnim.active = true;
            m_flameGraphZoomAnim.start0 = m_flameGraphViewStart;
            m_flameGraphZoomAnim.start1 = vStart;
            m_flameGraphZoomAnim.end0 = m_flameGraphViewEnd;
            m_flameGraphZoomAnim.end1 = vEnd;
            m_flameGraphZoomAnim.progress = 0;
        }

        FlameGraphContext ctx;
        ctx.draw = draw;
        ctx.wpos = wpos;
        ctx.dpos = ctx.wpos + ImVec2( 0.5f, 0.5f );
        ctx.w = w;
        ctx.ty = ImGui::GetTextLineHeight();
        ctx.ostep = ctx.ty + 1;
        ctx.pxns = region.x / double( m_flameGraphViewEnd - m_flameGraphViewStart );
        ctx.nspx = 1.0 / ctx.pxns;
        ctx.vStart = m_flameGraphViewStart;
        ctx.vEnd = m_flameGraphViewEnd;
        ctx.yMin = clipMin.y;
        ctx.yMax = clipMax.y;

        const auto MinVisNs = int64_t( round( GetScale() * MinVisSize * ctx.nspx ) );
        const auto contentHeight = GetFlameGraphDepth( m_flameGraphData, MinVisNs ) * ctx.ostep;
        ImGui::Dummy( ImVec2( 0, contentHeight ) );
        DrawFlameGraphLevel( m_flameGraphData, ctx, 0, m_flameMode == 1 );

        ImGui::EndChild();
    }

    ImGui::End();
}

}
