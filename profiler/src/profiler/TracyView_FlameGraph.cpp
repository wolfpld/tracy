#include "TracyEvent.hpp"
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

void View::DrawFlameGraph()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Flame graph", &m_showFlameGraph, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    ImGui::End();
}

}
