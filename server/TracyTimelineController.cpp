#include "imgui.h"

#include "TracyTimelineController.hpp"

namespace tracy
{

TimelineController::TimelineController()
    : m_height( 0 )
    , m_offset( 0 )
    , m_scroll( 0 )
{
}

void TimelineController::End( float offset )
{
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
