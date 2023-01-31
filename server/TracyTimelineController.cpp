#include <algorithm>

#include "imgui.h"

#include "TracyTimelineController.hpp"

namespace tracy
{

TimelineController::TimelineController( View& view, Worker& worker )
    : m_height( 0 )
    , m_scroll( 0 )
    , m_centerItemkey( nullptr )
    , m_centerItemOffsetY( 0 )
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

void TimelineController::UpdateCenterItem()
{
    ImVec2 mousePos = ImGui::GetMousePos();

    m_centerItemkey = nullptr;
    m_centerItemOffsetY = 0;

    if( m_firstFrame || !ImGui::IsMousePosValid( &mousePos ) ) return;

    const auto timelineMousePosY = mousePos.y - ImGui::GetWindowPos().y;
    int centerY = timelineMousePosY + ImGui::GetScrollY();

    int yBegin = 0;
    int yEnd = 0;
    for( auto& item : m_items )
    {
        m_centerItemkey = item->GetKey();
        yBegin = yEnd;
        yEnd += item->GetNextFrameHeight();

        const auto inLowerBounds = m_centerItemkey == m_items.front()->GetKey() || yBegin <= centerY;
        const auto inUpperBounds = m_centerItemkey == m_items.back()->GetKey() || centerY < yEnd;

        if( inLowerBounds && inUpperBounds )
        {
            m_centerItemOffsetY = centerY - yBegin;
            break;
        }
    }
}

std::optional<int> TimelineController::CalculateScrollPosition() const
{
    if( !m_centerItemkey ) return std::nullopt;

    ImVec2 mousePos = ImGui::GetMousePos();

    if( !ImGui::IsMousePosValid( &mousePos ) ) return std::nullopt;

    const auto timelineMousePosY = mousePos.y - ImGui::GetWindowPos().y;

    int yBegin = 0;
    int yEnd = 0;
    for( auto& item : m_items )
    {
        yBegin = yEnd;
        yEnd += item->GetNextFrameHeight();

        if( item->GetKey() != m_centerItemkey ) continue;

        int scrollY = yBegin + m_centerItemOffsetY - timelineMousePosY;

        return scrollY;
    }

    return std::nullopt;
}

void TimelineController::End( double pxns, const ImVec2& wpos, bool hover,  bool vcenter, float yMin, float yMax )
{
    auto shouldUpdateCenterItem = [&] () {
        const auto imguiChangedScroll = m_scroll != ImGui::GetScrollY();
        const auto& mouseDelta = ImGui::GetIO().MouseDelta;
        const auto mouseMoved = mouseDelta.x != 0.0f || mouseDelta.y != 0.0f;
        const auto& mousePos = ImGui::GetIO().MousePos;
        const auto mouseVisible = ImGui::IsMousePosValid( &mousePos );
        return ( ( imguiChangedScroll || mouseMoved || !mouseVisible ) && !ImGui::IsMouseDown( 1 ) ) || !m_centerItemkey;
    };

    if( !vcenter )
    {
        m_centerItemkey = nullptr;
        m_centerItemOffsetY = 0;
    }
    else if( shouldUpdateCenterItem() )
    {
        UpdateCenterItem();
    }

    int yOffset = 0;

    for( auto& item : m_items )
    {
        auto currentFrameItemHeight = item->GetNextFrameHeight();
        item->Draw( m_firstFrame, pxns, yOffset, wpos, hover, yMin, yMax );
        if( m_firstFrame ) currentFrameItemHeight = item->GetNextFrameHeight();
        yOffset += currentFrameItemHeight;
    }

    if( const auto scrollY = CalculateScrollPosition() )
    {
        int clampedScrollY = std::min<int>( *scrollY, yOffset );
        ImGui::SetScrollY( clampedScrollY );
        int minHeight = ImGui::GetWindowHeight() + clampedScrollY;
        yOffset = std::max( yOffset, minHeight );
    }

    const auto scrollPos = ImGui::GetScrollY();
    if( ( scrollPos == 0 && m_scroll != 0 ) || yOffset > m_height )
    {
        m_height = yOffset;
    }
    m_scroll = scrollPos;
}

}
