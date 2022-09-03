#ifndef __TRACYTIMELINECONTROLLER_HPP__
#define __TRACYTIMELINECONTROLLER_HPP__

#include <vector>

#include "../public/common/TracyForceInline.hpp"
#include "tracy_robin_hood.h"
#include "TracyTimelineItem.hpp"

namespace tracy
{

class TimelineController
{
    struct VisData
    {
        bool visible = true;
        bool showFull = true;
        bool ghost = false;
        int offset = 0;
        int height = 0;
    };

public:
    TimelineController( View& view, const Worker& worker );

    void FirstFrameExpired();
    void End( float offset );

    template<class T, class U>
    void AddItem( U* data )
    {
        auto it = m_itemMap.find( data );
        if( it == m_itemMap.end() ) it = m_itemMap.emplace( data, std::make_unique<T>( m_view, m_worker, data ) ).first;
        m_items.emplace_back( it->second.get() );
    }

    float GetHeight() const { return m_height; }
    const unordered_flat_map<const void*, VisData>& GetVisData() const { return m_visData; }

    void AdjustThreadHeight( VisData& vis, int oldOffset, int& offset );
    float AdjustThreadPosition( VisData& vis, float wy, int& offset );

    tracy_force_inline VisData& Vis( const void* ptr )
    {
        auto it = m_visData.find( ptr );
        if( it == m_visData.end() )
        {
            it = m_visData.emplace( ptr, VisData {} ).first;
        }
        return it->second;
    }

private:
    std::vector<TimelineItem*> m_items;
    unordered_flat_map<const void*, std::unique_ptr<TimelineItem>> m_itemMap;

    unordered_flat_map<const void*, VisData> m_visData;

    float m_height;
    float m_offset;
    float m_scroll;

    bool m_firstFrame;

    View& m_view;
    const Worker& m_worker;
};

}

#endif
