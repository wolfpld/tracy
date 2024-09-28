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

struct FlameGraphItem
{
    int64_t srcloc;
    int64_t time;
    Vector<FlameGraphItem> children;
};

void View::BuildFlameGraph( const Worker& worker, Vector<FlameGraphItem>& data, const Vector<short_ptr<ZoneEvent>>& zones )
{
    FlameGraphItem* it;
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
                it->time += duration;
                if( v.HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v.Child() );
                    BuildFlameGraph( worker, it->children, children );
                }
            }
            else
            {
                it = std::find_if( data.begin(), data.end(), [srcloc]( const auto& v ) { return v.srcloc == srcloc; } );
                if( it == data.end() )
                {
                    data.push_back( FlameGraphItem { srcloc, duration } );
                    if( v.HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v.Child() );
                        BuildFlameGraph( worker, data.back().children, children );
                    }
                    it = &data.back();
                }
                else
                {
                    it->time += duration;
                    if( v.HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v.Child() );
                        BuildFlameGraph( worker, it->children, children );
                    }
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
                it->time += duration;
                if( v->HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v->Child() );
                    BuildFlameGraph( worker, it->children, children );
                }
            }
            else
            {
                it = std::find_if( data.begin(), data.end(), [srcloc]( const auto& v ) { return v.srcloc == srcloc; } );
                if( it == data.end() )
                {
                    data.push_back( FlameGraphItem { srcloc, duration } );
                    if( v->HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v->Child() );
                        BuildFlameGraph( worker, data.back().children, children );
                    }
                    it = &data.back();
                }
                else
                {
                    it->time += duration;
                    if( v->HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v->Child() );
                        BuildFlameGraph( worker, it->children, children );
                    }
                }
                last = srcloc;
            }
        }
    }
}

void View::BuildFlameGraph( const Worker& worker, Vector<FlameGraphItem>& data, const Vector<short_ptr<ZoneEvent>>& zones, const ContextSwitch* ctx )
{
    assert( ctx );
    FlameGraphItem* it;
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
                it->time += duration;
                if( v.HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v.Child() );
                    BuildFlameGraph( worker, it->children, children, ctx );
                }
            }
            else
            {
                it = std::find_if( data.begin(), data.end(), [srcloc]( const auto& v ) { return v.srcloc == srcloc; } );
                if( it == data.end() )
                {
                    data.push_back( FlameGraphItem { srcloc, duration } );
                    if( v.HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v.Child() );
                        BuildFlameGraph( worker, data.back().children, children, ctx );
                    }
                    it = &data.back();
                }
                else
                {
                    it->time += duration;
                    if( v.HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v.Child() );
                        BuildFlameGraph( worker, it->children, children, ctx );
                    }
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
                it->time += duration;
                if( v->HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v->Child() );
                    BuildFlameGraph( worker, it->children, children, ctx );
                }
            }
            else
            {
                it = std::find_if( data.begin(), data.end(), [srcloc]( const auto& v ) { return v.srcloc == srcloc; } );
                if( it == data.end() )
                {
                    data.push_back( FlameGraphItem { srcloc, duration } );
                    if( v->HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v->Child() );
                        BuildFlameGraph( worker, data.back().children, children, ctx );
                    }
                    it = &data.back();
                }
                else
                {
                    it->time += duration;
                    if( v->HasChildren() )
                    {
                        auto& children = worker.GetZoneChildren( v->Child() );
                        BuildFlameGraph( worker, it->children, children, ctx );
                    }
                }
                last = srcloc;
            }
        }
    }
}

void View::BuildFlameGraph( const Worker& worker, Vector<FlameGraphItem>& data, const Vector<SampleData>& samples )
{
    for( auto& v : samples )
    {
        const auto cs = v.callstack.Val();
        const auto& callstack = worker.GetCallstack( cs );

        auto vec = &data;
        const auto csz = callstack.size();
        for( size_t i=csz; i>0; i--)
        {
            auto frame = worker.GetCallstackFrame( callstack[i-1] );
            if( frame )
            {
                for( uint8_t j=frame->size; j>0; j-- )
                {
                    const auto ip = frame->data[j-1].symAddr;
                    const auto symaddr = worker.GetInlineSymbolForAddress( ip );
                    if( symaddr != 0 )
                    {
                        auto it = std::find_if( vec->begin(), vec->end(), [symaddr]( const auto& v ) { return v.srcloc == symaddr; } );
                        if( it == vec->end() )
                        {
                            vec->push_back( FlameGraphItem { (int64_t)symaddr, 1 } );
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
        }
    }
}

static void SortFlameGraph( Vector<FlameGraphItem>& data )
{
    pdqsort_branchless( data.begin(), data.end(), []( const FlameGraphItem& lhs, const FlameGraphItem& rhs ) { return lhs.time > rhs.time; } );
    for( auto& v : data ) SortFlameGraph( v.children );
}

static void FreeVector( Vector<FlameGraphItem>& data )
{
    for( auto& v : data )
    {
        FreeVector( v.children );
        v.children.~Vector();
    }
}

struct FlameGraphContext
{
    ImDrawList* draw;
    ImVec2 wpos;
    ImVec2 dpos;
    float ty;
    float ostep;
    double pxns;
    double nxps;
};

void View::DrawFlameGraphItem( const FlameGraphItem& item, FlameGraphContext& ctx, uint64_t ts, int depth, bool samples )
{
    const auto x0 = ctx.dpos.x + ts * ctx.pxns;
    const auto x1 = x0 + item.time * ctx.pxns;
    const auto y0 = ctx.dpos.y + depth * ctx.ostep;
    const auto y1 = y0 + ctx.ty;

    const SourceLocation* srcloc;
    uint32_t color;
    const char* name;
    const char* slName;

    if( !samples )
    {
        srcloc = &m_worker.GetSourceLocation( item.srcloc );
        color = GetSrcLocColor( *srcloc, depth );
        name = slName = m_worker.GetString( srcloc->name.active ? srcloc->name : srcloc->function );
    }
    else
    {
        auto sym = m_worker.GetSymbolData( (uint64_t)item.srcloc );
        if( sym )
        {
            name = m_worker.GetString( sym->name );
            auto namehash = charutil::hash( name );
            if( namehash == 0 ) namehash++;
            color = GetHsvColor( namehash, depth );
        }
        else
        {
            name = "???";
            color = 0xFF888888;
        }
        if( sym->isInline )
        {
            color = DarkenColorHalf( color );
        }
    }

    const auto hiColor = HighlightColor( color );
    const auto darkColor = DarkenColor( color );

    const auto zsz = x1 - x0;

    auto tsz = ImGui::CalcTextSize( name );
    if( m_vd.shortenName == ShortenName::Always || ( ( m_vd.shortenName == ShortenName::NoSpace || m_vd.shortenName == ShortenName::NoSpaceAndNormalize ) && tsz.x > zsz ) )
    {
        name = ShortenZoneName( m_vd.shortenName, name, tsz, zsz );
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
        DrawTextContrast( ctx.draw, ImVec2( x, y0 ), 0xFFFFFFFF, name );
    }
    else
    {
        ImGui::PushClipRect( ImVec2( x0, y0 ), ImVec2( x1, y1 ), true );
        DrawTextContrast( ctx.draw, ImVec2( x0, y0 ), 0xFFFFFFFF, name );
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
                auto name = m_worker.GetString( sym->name );
                auto normalized = m_vd.shortenName == ShortenName::Never ? name : ShortenZoneName( ShortenName::OnlyNormalize, name );
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

    uint64_t cts = ts;
    for( auto& v : item.children )
    {
        DrawFlameGraphItem( v, ctx, cts, depth+1, samples );
        cts += v.time;
    }
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

void View::DrawFlameGraph()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Flame graph", &m_showFlameGraph, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
    ImGui::RadioButton( ICON_FA_SYRINGE " Instrumentation", &m_flameMode, 0 );

    if( m_worker.AreCallstackSamplesReady() && m_worker.GetCallstackSampleCount() > 0 )
    {
        ImGui::SameLine();
        ImGui::RadioButton( ICON_FA_EYE_DROPPER " Sampling", &m_flameMode, 1 );
    }

    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();

    ImGui::Checkbox( ICON_FA_ARROW_UP_WIDE_SHORT " Sort by time", &m_flameSort );

    if( m_flameMode == 0 )
    {
        if( m_worker.HasContextSwitches() )
        {
            ImGui::SameLine();
            ImGui::Checkbox( "Running time", &m_flameRunningTime );
        }
        else
        {
            assert( !m_flameRunningTime );
        }
    }

    auto expand = ImGui::TreeNode( ICON_FA_SHUFFLE " Visible threads:" );
    ImGui::SameLine();
    size_t visibleThreads = 0;
    size_t tsz = 0;
    for( const auto& t : m_threadOrder )
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
            for( const auto& t : m_threadOrder )
            {
                FlameGraphThread( t->id ) = true;
            }
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                FlameGraphThread( t->id ) = false;
            }
        }

        int idx = 0;
        for( const auto& t : m_threadOrder )
        {
            ImGui::PushID( idx++ );
            const auto threadColor = GetThreadColor( t->id, 0 );
            SmallColorBox( threadColor );
            ImGui::SameLine();
            SmallCheckbox( m_worker.GetThreadName( t->id ), &FlameGraphThread( t->id ) );
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

    Vector<FlameGraphItem> data;

    if( m_flameMode == 0 )
    {
        for( auto& thread : m_worker.GetThreadData() )
        {
            if( FlameGraphThread( thread->id ) )
            {
                if( m_flameRunningTime )
                {
                    const auto ctx = m_worker.GetContextSwitchData( thread->id );
                    if( ctx ) BuildFlameGraph( m_worker, data, thread->timeline, ctx );
                }
                else
                {
                    BuildFlameGraph( m_worker, data, thread->timeline );
                }
            }
        }
    }
    else
    {
        for( auto& thread : m_worker.GetThreadData() )
        {
            if( FlameGraphThread( thread->id ) ) BuildFlameGraph( m_worker, data, thread->samples );
        }
    }

    if( m_flameSort ) SortFlameGraph( data );

    int64_t zsz = 0;
    for( auto& v : data ) zsz += v.time;

    ImGui::BeginChild( "##flameGraph" );
    const auto region = ImGui::GetContentRegionAvail();

    if( data.empty() )
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
        ctx.nxps = 1.0 / ctx.pxns;

        ImGui::ItemSize( region );
        uint64_t ts = 0;
        for( auto& v : data )
        {
            DrawFlameGraphItem( v, ctx, ts, 0, m_flameMode == 1 );
            ts += v.time;
        }
    }

    ImGui::EndChild();

    ImGui::End();
    FreeVector( data );
}

}
