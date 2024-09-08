#include "TracyColor.hpp"
#include "TracyEvent.hpp"
#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyVector.hpp"
#include "TracyView.hpp"
#include "tracy_robin_hood.h"

namespace tracy
{

struct FlameGraphItem
{
    int16_t srcloc;
    int64_t time;
    Vector<FlameGraphItem> children;
};

static void BuildFlameGraph( const Worker& worker, Vector<FlameGraphItem>& data, const Vector<short_ptr<ZoneEvent>>& zones )
{
    unordered_flat_map<int16_t, uint16_t> map;
    for( size_t i=0; i<data.size(); i++ ) map.emplace( data[i].srcloc, i );

    if( zones.is_magic() )
    {
        auto& vec = *(Vector<ZoneEvent>*)&zones;
        for( auto& v : vec )
        {
            if( !v.IsEndValid() ) break;
            const auto srcloc = v.SrcLoc();
            const auto duration = v.End() - v.Start();
            auto it = map.find( srcloc );
            if( it == map.end() )
            {
                map.emplace( srcloc, data.size() );
                data.push_back( FlameGraphItem { srcloc, duration } );
                if( v.HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v.Child() );
                    BuildFlameGraph( worker, data.back().children, children );
                }
            }
            else
            {
                auto& item = data[it->second];
                item.time += duration;
                if( v.HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v.Child() );
                    BuildFlameGraph( worker, item.children, children );
                }
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
            auto it = map.find( srcloc );
            if( it == map.end() )
            {
                map.emplace( srcloc, data.size() );
                data.push_back( FlameGraphItem { srcloc, duration } );
                if( v->HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v->Child() );
                    BuildFlameGraph( worker, data.back().children, children );
                }
            }
            else
            {
                auto& item = data[it->second];
                item.time += duration;
                if( v->HasChildren() )
                {
                    auto& children = worker.GetZoneChildren( v->Child() );
                    BuildFlameGraph( worker, item.children, children );
                }
            }
        }
    }
}

static void SortFlameGraph( Vector<FlameGraphItem>& data )
{
    std::sort( data.begin(), data.end(), []( const FlameGraphItem& lhs, const FlameGraphItem& rhs ) { return lhs.time > rhs.time; } );
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

void View::DrawFlameGraphItem( const FlameGraphItem& item, FlameGraphContext& ctx, uint64_t ts, int depth )
{
    const auto x0 = ctx.dpos.x + ts * ctx.pxns;
    const auto x1 = x0 + item.time * ctx.pxns;
    const auto y0 = ctx.dpos.y + depth * ctx.ostep;
    const auto y1 = y0 + ctx.ty;

    const auto& srcloc = m_worker.GetSourceLocation( item.srcloc );
    const auto color = GetSrcLocColor( srcloc, depth );
    const auto hiColor = HighlightColor( color );
    const auto darkColor = DarkenColor( color );

    const auto zsz = x1 - x0;
    const char* slName = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
    const char* name = slName;

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
        if( srcloc.name.active )
        {
            ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
        }
        ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
        ImGui::Separator();
        SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
        ImGui::SameLine();
        ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
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

        if( ImGui::IsMouseClicked( 0 ) )
        {
            m_findZone.ShowZone( item.srcloc, slName );
        }
    }

    uint64_t cts = ts;
    for( auto& v : item.children )
    {
        DrawFlameGraphItem( v, ctx, cts, depth+1 );
        cts += v.time;
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

    ImGui::Separator();
    ImGui::PopStyleVar();

    Vector<FlameGraphItem> data;

    for( auto& thread : m_worker.GetThreadData() ) BuildFlameGraph( m_worker, data, thread->timeline );
    SortFlameGraph( data );

    int64_t zsz = 0;
    for( auto& v : data ) zsz += v.time;

    ImGui::BeginChild( "##flameGraph" );

    const auto region = ImGui::GetContentRegionAvail();
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
        DrawFlameGraphItem( v, ctx, ts, 0 );
        ts += v.time;
    }

    ImGui::EndChild();

    ImGui::End();
    FreeVector( data );
}

}
