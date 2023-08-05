#include <algorithm>
#include <thread>

#include "TracyTimelineItem.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineController.hpp"
#include "TracyView.hpp"

namespace tracy
{

TimelineController::TimelineController( View& view, Worker& worker, bool threading )
    : m_height( 0 )
    , m_scroll( 0 )
    , m_centerItemkey( nullptr )
    , m_centerItemOffsetY( 0 )
    , m_firstFrame( true )
    , m_view( view )
    , m_worker( worker )
#ifdef __EMSCRIPTEN__
    , m_td( 0, "Render" )
#else
    , m_td( threading ? (size_t)std::max( 0, ( (int)std::thread::hardware_concurrency() - 2 ) / 2 ) : 0, "Render" )
#endif
{
}

TimelineController::~TimelineController()
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
        yEnd += item->GetHeight();

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
        yEnd += item->GetHeight();

        if( item->GetKey() != m_centerItemkey ) continue;

        int scrollY = yBegin + m_centerItemOffsetY - timelineMousePosY;

        return scrollY;
    }

    return std::nullopt;
}

void TimelineController::End( double pxns, const ImVec2& wpos, bool hover, bool vcenter, float yMin, float yMax, ImFont* smallFont )
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

    const auto& viewData = m_view.GetViewData();

    TimelineContext ctx;
    ctx.w = ImGui::GetContentRegionAvail().x - 1;
    ctx.ty = ImGui::GetTextLineHeight();
    ImGui::PushFont( smallFont );
    ctx.sty = ImGui::GetTextLineHeight();
    ImGui::PopFont();
    ctx.scale = GetScale();
    ctx.yMin = yMin;
    ctx.yMax = yMax;
    ctx.pxns = pxns;
    ctx.nspx = 1.0 / pxns;
    ctx.vStart = viewData.zvStart;
    ctx.vEnd = viewData.zvEnd;
    ctx.wpos = wpos;
    ctx.hover = hover;

    int yOffset = 0;
    for( auto& item : m_items )
    {
        if( item->WantPreprocess() && item->IsVisible() )
        {
            const auto yPos = wpos.y + yOffset;
            const bool visible = m_firstFrame || ( yPos < yMax && yPos + item->GetHeight() >= yMin );
            item->Preprocess( ctx, m_td, visible, yPos );
        }
        yOffset += m_firstFrame ? 0 : item->GetHeight();
    }
    m_td.Sync();

    yOffset = 0;
    for( auto& item : m_items )
    {
        auto currentFrameItemHeight = item->GetHeight();
        item->Draw( m_firstFrame, ctx, yOffset );
        if( m_firstFrame ) currentFrameItemHeight = item->GetHeight();
        yOffset += currentFrameItemHeight;
    }

    if( const auto scrollY = CalculateScrollPosition() )
    {
        int clampedScrollY = std::min<int>( *scrollY, std::max<int>( yOffset - ImGui::GetWindowHeight(), 0 ) );
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
