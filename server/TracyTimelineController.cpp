#include "imgui.h"

#include "TracyTimelineController.hpp"

namespace tracy
{

TimelineController::TimelineController( View& view, Worker& worker )
    : m_height( 0 )
    , m_scroll( 0 )
    , m_firstFrame( true )
    , m_view( view )
    , m_worker( worker )
{
}

void TimelineController::FirstFrameExpired()
{
    m_firstFrame = false;
}

void TimelineController::Begin()
{
    m_items.clear();
}

void TimelineController::End( double pxns, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    int yOffset = 0;

    for( auto& item : m_items )
    {
        item->Draw( m_firstFrame, pxns, yOffset, wpos, hover, yMin, yMax );
        yOffset += item->GetNextFrameHeight();
    }

    const auto scrollPos = ImGui::GetScrollY();
    if( ( scrollPos == 0 && m_scroll != 0 ) || yOffset > m_height )
    {
        m_height = yOffset;
    }
    m_scroll = scrollPos;
}

}
