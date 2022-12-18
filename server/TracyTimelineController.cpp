#include "imgui.h"

#include "TracyTimelineController.hpp"

namespace tracy
{

TimelineController::TimelineController( View& view, Worker& worker )
    : m_height( 0 )
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

    m_height = offset;
}

}
