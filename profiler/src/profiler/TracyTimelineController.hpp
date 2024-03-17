#ifndef __TRACYTIMELINECONTROLLER_HPP__
#define __TRACYTIMELINECONTROLLER_HPP__

#include <assert.h>
#include <optional>
#include <vector>

#include "TracyImGui.hpp"
#include "../server/TracyTaskDispatch.hpp"
#include "../server/tracy_robin_hood.h"
#include "../public/common/TracyForceInline.hpp"

namespace tracy
{

class TimelineItem;
class View;
class Worker;

class TimelineController
{
public:
    TimelineController( View& view, Worker& worker, bool threading );
    ~TimelineController();

    void FirstFrameExpired();
    void Begin();
    void End( double pxns, const ImVec2& wpos, bool hover, bool vcenter, float yMin, float yMax, ImFont* smallFont );

    template<class T, class U>
    void AddItem( U* data )
    {
        auto it = m_itemMap.find( data );
        if( it == m_itemMap.end() ) it = m_itemMap.emplace( data, std::make_unique<T>( m_view, m_worker, data ) ).first;
        m_items.emplace_back( it->second.get() );
    }

    float GetHeight() const { return m_height; }
    const unordered_flat_map<const void*, std::unique_ptr<TimelineItem>>& GetItemMap() const { return m_itemMap; }

    tracy_force_inline TimelineItem& GetItem( const void* data )
    {
        auto it = m_itemMap.find( data );
        assert( it != m_itemMap.end() );
        return *it->second;
    }

private:
    void UpdateCenterItem();
    std::optional<int> CalculateScrollPosition() const;

    std::vector<TimelineItem*> m_items;
    unordered_flat_map<const void*, std::unique_ptr<TimelineItem>> m_itemMap;

    float m_height;
    float m_scroll;

    const void* m_centerItemkey;
    int m_centerItemOffsetY;

    bool m_firstFrame;

    View& m_view;
    Worker& m_worker;

    TaskDispatch m_td;
};

}

#endif
