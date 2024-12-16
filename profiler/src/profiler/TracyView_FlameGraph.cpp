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
            const auto duration = v.End() - v.Start();
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
            const auto duration = v->End() - v->Start();
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
            uint64_t cnt;
            if( !GetZoneRunningTime( ctx, v, duration, cnt ) ) break;
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
            uint64_t cnt;
            if( !GetZoneRunningTime( ctx, *v, duration, cnt ) ) break;
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

void View::BuildFlameGraph( const Worker& worker, std::vector<FlameGraphItem>& data, const Vector<SampleData>& samples )
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
                    for( uint8_t j=frameData->size; j>0; j-- )
                    {
                        const auto frame = frameData->data[j-1];
                        const auto symaddr = frame.symAddr;
                        if( symaddr != 0 )
                        {
                            auto filename = m_worker.GetString( frame.file );
                            auto image = frameData->imageName.Active() ? m_worker.GetString( frameData->imageName ) : nullptr;
                            if( !IsFrameExternal( filename, image ) )
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
                    for( uint8_t j=frameData->size; j>0; j-- )
                    {
                        const auto frame = frameData->data[j-1];
                        const auto symaddr = frame.symAddr;
                        if( symaddr != 0 )
                        {
                            auto filename = m_worker.GetString( frame.file );
                            auto image = frameData->imageName.Active() ? m_worker.GetString( frameData->imageName ) : nullptr;
                            cache.emplace_back( FrameCache { symaddr, frame.name, IsFrameExternal( filename, image ) } );
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

        auto vec = &data;
        for( auto& v : cache )
        {
            auto it = std::find_if( vec->begin(), vec->end(), [symaddr = v.symaddr]( const auto& v ) { return v.srcloc == symaddr; } );
            if( it == vec->end() )
            {
                vec->emplace_back( FlameGraphItem { (int64_t)v.symaddr, 1, v.name } );
                vec = &vec->back().children;
            }
            else
            {
                it->time++;
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
    float ty;
    float ostep;
    double pxns;
    double nspx;
    int64_t vStart;
    int64_t vEnd;
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
            draw->AddRectFilled( ImVec2( wpos.x + px0, wpos.y + depth * ostep ), ImVec2( wpos.x + std::max( px1, px0 + MinVisSize ), wpos.y + ( depth + 1 ) * ostep ), 0xFF666666 );
            DrawZigZag( draw, ImVec2( wpos.x, wpos.y + ( depth + 0.5f ) * ostep ), px0, std::max( px1, px0 + MinVisSize ), ctx.ty / 4, 0xFF444444 );
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
    const auto x0 = ctx.dpos.x + item.begin * ctx.pxns;
    const auto x1 = x0 + item.time * ctx.pxns;
    const auto y0 = ctx.dpos.y + depth * ctx.ostep;
    const auto y1 = y0 + ctx.ty;

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

    const bool hover = ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect( ImVec2( x0, y0 ), ImVec2( x1, y1 ) );

    ctx.draw->AddRectFilled( ImVec2( x0, y0 ), ImVec2( x1, y1 ), color );
    if( hover )
    {
        ctx.draw->AddRect( ImVec2( x0 - 0.5f, y0 - 0.5f ), ImVec2( x1 - 0.5f, y1 - 0.5f ), 0xFFEEEEEE );
    }
    else
    {
        DrawLine( ctx.draw, ImVec2( x0, y1 ), ImVec2( x0, y0 ), ImVec2( x1-1, y0 ), hiColor );
        DrawLine( ctx.draw, ImVec2( x0, y1 ), ImVec2( x1-1, y1), ImVec2( x1-1, y0 ), darkColor );
    }

    if( tsz.x < zsz )
    {
        const auto x = ( x1 + x0 - tsz.x ) * 0.5;
        DrawTextContrast( ctx.draw, ImVec2( x, y0 ), textColor, normalized );
    }
    else
    {
        ImGui::PushClipRect( ImVec2( x0, y0 ), ImVec2( x1, y1 ), true );
        DrawTextContrast( ctx.draw, ImVec2( x0, y0 ), textColor, normalized );
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
                ImGui::PushFont( m_smallFont );
                ImGui::AlignTextToFramePadding();
                ImGui::TextDisabled( "0x%" PRIx64, symAddr );
                ImGui::PopFont();
                if( normalized != name && strcmp( normalized, name ) != 0 )
                {
                    ImGui::PushFont( m_smallFont );
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
                const auto period = m_worker.GetSamplingPeriod();
                TextFocused( "Execution time:", TimeToString( item.time * period ) );
                if( !item.children.empty() )
                {
                    TextFocused( "Self time:", TimeToString( self * period ) );
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

void View::DrawFlameGraphHeader( uint64_t timespan )
{
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto w = ImGui::GetContentRegionAvail().x;// - ImGui::GetStyle().ScrollbarSize;
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetTextLineHeight();
    const auto ty025 = round( ty * 0.25f );
    const auto ty0375 = round( ty * 0.375f );
    const auto ty05 = round( ty * 0.5f );

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


void View::DrawFlameGraph()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Flame graph", &m_showFlameGraph, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
    if( ImGui::RadioButton( ICON_FA_SYRINGE " Instrumentation", &m_flameMode, 0 ) ) m_flameGraphInvariant.Reset();

    if( m_worker.AreCallstackSamplesReady() && m_worker.GetCallstackSampleCount() > 0 )
    {
        ImGui::SameLine();
        if( ImGui::RadioButton( ICON_FA_EYE_DROPPER " Sampling", &m_flameMode, 1 ) ) m_flameGraphInvariant.Reset();
    }

    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();

    if( ImGui::Checkbox( ICON_FA_ARROW_UP_WIDE_SHORT " Sort by time", &m_flameSort ) ) m_flameGraphInvariant.Reset();

    if( m_flameMode == 0 )
    {
        if( m_worker.HasContextSwitches() )
        {
            ImGui::SameLine();
            if( ImGui::Checkbox( "Running time", &m_flameRunningTime ) ) m_flameGraphInvariant.Reset();
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
        if( ImGui::Checkbox( "Frames", &m_flameExternal ) ) m_flameGraphInvariant.Reset();
        ImGui::SameLine();
        if( m_flameExternal ) ImGui::BeginDisabled();
        if( ImGui::Checkbox( "Tails", &m_flameExternalTail ) ) m_flameGraphInvariant.Reset();
        if( m_flameExternal ) ImGui::EndDisabled();
    }

    auto& td = m_worker.GetThreadData();
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
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : td )
            {
                FlameGraphThread( t->id ) = false;
            }
            m_flameGraphInvariant.Reset();
        }

        int idx = 0;
        for( const auto& t : td )
        {
            ImGui::PushID( idx++ );
            const auto threadColor = GetThreadColor( t->id, 0 );
            SmallColorBox( threadColor );
            ImGui::SameLine();
            if( SmallCheckbox( m_worker.GetThreadName( t->id ), &FlameGraphThread( t->id ) ) ) m_flameGraphInvariant.Reset();
            ImGui::PopID();
            if( t->isFiber )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
        }
        ImGui::TreePop();
    }

    ImGui::Separator();
    ImGui::PopStyleVar();

    if( m_flameMode == 0 && ( m_flameGraphInvariant.count != m_worker.GetZoneCount() || m_flameGraphInvariant.lastTime != m_worker.GetLastTime() ) ||
        m_flameMode == 1 && ( m_flameGraphInvariant.count != m_worker.GetCallstackSampleCount() ) )
    {
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
                        BuildFlameGraph( m_worker, threadData[idx], thread->samples );
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
    }

    int64_t zsz = 0;
    for( auto& v : m_flameGraphData ) zsz += v.time;

    ImGui::BeginChild( "##flameGraph" );
    const auto region = ImGui::GetContentRegionAvail();

    if( m_flameGraphData.empty() )
    {
        ImGui::PushFont( m_bigFont );
        ImGui::Dummy( ImVec2( 0, ( region.y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
        TextCentered( ICON_FA_CAT );
        TextCentered( "No data available to display" );
        ImGui::PopFont();
    }
    else
    {
        DrawFlameGraphHeader( m_flameMode == 0 ? zsz : zsz * m_worker.GetSamplingPeriod() );

        FlameGraphContext ctx;
        ctx.draw = ImGui::GetWindowDrawList();
        ctx.wpos = ImGui::GetCursorScreenPos();
        ctx.dpos = ctx.wpos + ImVec2( 0.5f, 0.5f );
        ctx.ty = ImGui::GetTextLineHeight();
        ctx.ostep = ctx.ty + 1;
        ctx.pxns = region.x / zsz;
        ctx.nspx = 1.0 / ctx.pxns;
        ctx.vStart = 0;
        ctx.vEnd = zsz;

        ImGui::ItemSize( region );
        DrawFlameGraphLevel( m_flameGraphData, ctx, 0, m_flameMode == 1 );
    }

    ImGui::EndChild();

    ImGui::End();
}

}
