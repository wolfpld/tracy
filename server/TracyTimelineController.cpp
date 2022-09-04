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

void TimelineController::End( double pxns, int offset, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    for( auto& item : m_items )
    {
        item->Draw( m_firstFrame, pxns, offset, wpos, hover, yMin, yMax );
    }

    const auto scrollPos = ImGui::GetScrollY();
    if( scrollPos == 0 && m_scroll != 0 )
    {
        m_height = 0;
    }
    else
    {
        if( offset > m_height ) m_height = offset;
    }
    m_scroll = scrollPos;
}

}
