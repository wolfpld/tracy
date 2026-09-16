#include <algorithm>
#include <thread>

#include "TracyTimelineItem.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineController.hpp"
#include "TracyView.hpp"

#include "../Fonts.hpp"

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
    , m_td( threading ? 2 : 0, "Render" )
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

void TimelineController::UpdateCenterItem( int pinnedTop )
{
    ImVec2 mousePos = ImGui::GetMousePos();

    m_centerItemkey = nullptr;
    m_centerItemOffsetY = 0;

    if( m_firstFrame || !ImGui::IsMousePosValid( &mousePos ) ) return;

    const auto timelineMousePosY = mousePos.y - ImGui::GetWindowPos().y;
    int centerY = timelineMousePosY + ImGui::GetScrollY();

    // Pinned items are fixed to the viewport and excluded from the scrolling
    // flow, so centering only considers the normal items in the middle band.
    const void* firstNormalKey = nullptr;
    const void* lastNormalKey = nullptr;
    for( auto& item : m_items )
    {
        if( item->IsPinned() ) continue;
        if( !firstNormalKey ) firstNormalKey = item->GetKey();
        lastNormalKey = item->GetKey();
    }

    int yBegin = 0;
    int yEnd = pinnedTop;
    for( auto& item : m_items )
    {
        if( item->IsPinned() ) continue;
        m_centerItemkey = item->GetKey();
        yBegin = yEnd;
        yEnd += item->GetHeight();

        const auto inLowerBounds = m_centerItemkey == firstNormalKey || yBegin <= centerY;
        const auto inUpperBounds = m_centerItemkey == lastNormalKey || centerY < yEnd;

        if( inLowerBounds && inUpperBounds )
        {
            m_centerItemOffsetY = centerY - yBegin;
            break;
        }
    }
}

std::optional<int> TimelineController::CalculateScrollPosition( int pinnedTop ) const
{
    if( !m_centerItemkey ) return std::nullopt;

    ImVec2 mousePos = ImGui::GetMousePos();

    if( !ImGui::IsMousePosValid( &mousePos ) ) return std::nullopt;

    const auto timelineMousePosY = mousePos.y - ImGui::GetWindowPos().y;

    int yBegin = 0;
    int yEnd = pinnedTop;
    for( auto& item : m_items )
    {
        if( item->IsPinned() ) continue;
        yBegin = yEnd;
        yEnd += item->GetHeight();

        if( item->GetKey() != m_centerItemkey ) continue;

        int scrollY = yBegin + m_centerItemOffsetY - timelineMousePosY;

        return scrollY;
    }

    // A "just-pinned" center item is gone from the normal run but will be
    // "re-picked" on next mouse move.
    return std::nullopt;
}

void TimelineController::End( double pxns, const ImVec2& wpos, bool hover, bool vcenter, float yMin, float yMax )
{
    // GetHeight() is 0 on the first frame, so the scroll extent would be shorter
    // if a track was pinned at load, but would "self-correct" in the next frame.
    // (Also, nothing is pinned at load anyway.)
    int pinnedTop = 0;
    int pinnedBottom = 0;
    for( auto& item : m_items )
    {
        if( !item->IsPinned() ) continue;
        if( item->PinToBottom() ) pinnedBottom += item->GetHeight();
        else pinnedTop += item->GetHeight();
    }

    auto shouldUpdateCenterItem = [&] () {
        const auto imguiChangedScroll = m_scroll != ImGui::GetScrollY();
        const auto& mouseDelta = ImGui::GetIO().MouseDelta;
        const auto mouseMoved = mouseDelta.x != 0.0f || mouseDelta.y != 0.0f;
        const auto& mousePos = ImGui::GetIO().MousePos;
        const auto mouseVisible = ImGui::IsMousePosValid( &mousePos );
        return ( ( imguiChangedScroll || mouseMoved || !mouseVisible ) && !ImGui::IsMouseDown( ImGuiMouseButton_Right ) ) || !m_centerItemkey;
    };

    if( !vcenter )
    {
        m_centerItemkey = nullptr;
        m_centerItemOffsetY = 0;
    }
    else if( shouldUpdateCenterItem() )
    {
        UpdateCenterItem( pinnedTop );
    }

    const auto& viewData = m_view.GetViewData();

    TimelineContext ctx;
    ctx.w = ImGui::GetContentRegionAvail().x - 1;
    ctx.ty = ImGui::GetTextLineHeight();
    ImGui::PushFont( g_fonts.normal, FontSmall );
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

    const int curScrollY = (int)ImGui::GetScrollY();
    const int windowHeight = (int)ImGui::GetWindowHeight();
    // Keep the pinned bands from overlapping (top wins), otherwise bottom items
    // would cover top ones while leaving them clickable underneath.
    const int bottomStart = std::max( curScrollY + pinnedTop, curScrollY + windowHeight - pinnedBottom );

    // Pinned items add the scroll offset so they stay fixed as content scrolls.
    auto itemYOffset = [&] ( TimelineItem* item, int topRun, int normalRun, int bottomRun ) -> int {
        if( !item->IsPinned() ) return pinnedTop + normalRun;
        return item->PinToBottom() ? bottomStart + bottomRun : curScrollY + topRun;
    };

    int topOffset = 0, normalOffset = 0, bottomOffset = 0;
    for( auto& item : m_items )
    {
        const int off = itemYOffset( item, topOffset, normalOffset, bottomOffset );
        if( item->WantPreprocess() && item->IsVisible() )
        {
            const auto yPos = wpos.y + off;
            const bool visible = item->IsPinned() || m_firstFrame || ( yPos < yMax && yPos + item->GetHeight() >= yMin );
            item->Preprocess( ctx, m_td, visible, yPos );
        }
        const int h = m_firstFrame ? 0 : item->GetHeight();
        if( !item->IsPinned() ) normalOffset += h;
        else if( item->PinToBottom() ) bottomOffset += h;
        else topOffset += h;
    }
    m_td.Sync();

    auto draw = ImGui::GetWindowDrawList();
    const auto bgColor = ImGui::GetColorU32( ImGuiCol_WindowBg );

    // Keep tracks scrolling under a pinned band inert (cull their headers to the
    // middle region and drop hover while the mouse is over a band).
    TimelineContext ctxNormal = ctx;
    if( pinnedTop > 0 ) ctxNormal.yMin = std::max<float>( ctx.yMin, wpos.y + curScrollY + pinnedTop );
    if( pinnedBottom > 0 ) ctxNormal.yMax = std::min<float>( ctx.yMax, wpos.y + bottomStart );
    const auto mouseY = ImGui::GetMousePos().y;
    const bool mouseInTopBand = pinnedTop > 0 && mouseY >= wpos.y + curScrollY && mouseY < wpos.y + curScrollY + pinnedTop;
    const bool mouseInBottomBand = pinnedBottom > 0 && mouseY >= wpos.y + bottomStart && mouseY < wpos.y + curScrollY + windowHeight;
    ctxNormal.hover = ctx.hover && !mouseInTopBand && !mouseInBottomBand;
    int normalRunning = 0;
    for( auto& item : m_items )
    {
        if( item->IsPinned() ) continue;
        auto h = item->GetHeight();
        item->Draw( m_firstFrame, ctxNormal, pinnedTop + normalRunning );
        if( m_firstFrame ) h = item->GetHeight();
        normalRunning += h;
    }

    if( pinnedTop > 0 ) draw->AddRectFilled( ImVec2( wpos.x, wpos.y + curScrollY ), ImVec2( wpos.x + ctx.w, wpos.y + curScrollY + pinnedTop ), bgColor );
    int topRunning = 0;
    for( auto& item : m_items )
    {
        if( !item->IsPinned() || item->PinToBottom() ) continue;
        auto h = item->GetHeight();
        item->Draw( m_firstFrame, ctx, curScrollY + topRunning );
        if( m_firstFrame ) h = item->GetHeight();
        topRunning += h;
    }

    if( pinnedBottom > 0 ) draw->AddRectFilled( ImVec2( wpos.x, wpos.y + bottomStart ), ImVec2( wpos.x + ctx.w, wpos.y + curScrollY + windowHeight ), bgColor );
    int bottomRunning = 0;
    for( auto& item : m_items )
    {
        if( !item->IsPinned() || !item->PinToBottom() ) continue;
        auto h = item->GetHeight();
        item->Draw( m_firstFrame, ctx, bottomStart + bottomRunning );
        if( m_firstFrame ) h = item->GetHeight();
        bottomRunning += h;
    }

    int yOffset = pinnedTop + normalRunning + pinnedBottom;

    if( const auto scrollY = CalculateScrollPosition( pinnedTop ) )
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
