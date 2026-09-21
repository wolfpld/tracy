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
    if( m_normalItems.empty() ) return;
    const void* firstNormalKey = m_normalItems.front()->GetKey();
    const void* lastNormalKey = m_normalItems.back()->GetKey();

    int yBegin = 0;
    int yEnd = pinnedTop;
    for( auto& item : m_normalItems )
    {
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
    for( auto& item : m_normalItems )
    {
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
    // Snapshot the pin classification once per frame before any Draw runs.
    // Toggling a pin flips its state mid-frame and since re-checking it in
    // the draw passes would draw the item twice (normal and band passes),
    // the grouping here defers the change to the next frame.
    // GetHeight() is 0 on the first frame, so the scroll extent would be shorter
    // if a track was pinned at load, but self-corrects next frame (and nothing is
    // pinned at load anyway).
    m_normalItems.clear();
    m_pinnedTopItems.clear();
    m_pinnedBottomItems.clear();
    int pinnedTop = 0;
    int pinnedBottom = 0;
    for( auto& item : m_items )
    {
        if( !item->IsPinned() ) m_normalItems.push_back( item );
        else if( item->PinToBottom() ) { m_pinnedBottomItems.push_back( item ); pinnedBottom += item->GetHeight(); }
        else { m_pinnedTopItems.push_back( item ); pinnedTop += item->GetHeight(); }
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

    // Screen-space band edges, shared by culling, the mouse tests, and the fills.
    const float topBandBegin = wpos.y + curScrollY;
    const float topBandEnd = topBandBegin + pinnedTop;
    const float bottomBandBegin = wpos.y + bottomStart;
    const float bottomBandEnd = topBandBegin + windowHeight;

    TimelineContext ctxNormal = ctx;
    if( pinnedTop > 0 ) ctxNormal.yMin = std::max<float>( ctx.yMin, topBandEnd );
    if( pinnedBottom > 0 ) ctxNormal.yMax = std::min<float>( ctx.yMax, bottomBandBegin );
    const auto mouseY = ImGui::GetMousePos().y;
    const bool mouseInTopBand = pinnedTop > 0 && mouseY >= topBandBegin && mouseY < topBandEnd;
    const bool mouseInBottomBand = pinnedBottom > 0 && mouseY >= bottomBandBegin && mouseY < bottomBandEnd;
    ctxNormal.hover = ctx.hover && !mouseInTopBand && !mouseInBottomBand;

    // Preprocess runs before any Draw, so live pin state is stable here. Normal
    // items are culled to the middle band and pinned items are always on screen.
    int topOffset = 0, normalOffset = 0, bottomOffset = 0;
    for( auto& item : m_items )
    {
        const bool pinned = item->IsPinned();
        const bool toBottom = pinned && item->PinToBottom();
        const int off = !pinned ? pinnedTop + normalOffset : toBottom ? bottomStart + bottomOffset : curScrollY + topOffset;
        if( item->WantPreprocess() && item->IsVisible() )
        {
            const auto yPos = wpos.y + off;
            const bool visible = pinned || m_firstFrame || ( yPos < ctxNormal.yMax && yPos + item->GetHeight() >= ctxNormal.yMin );
            item->Preprocess( ctx, m_td, visible, yPos );
        }
        const int h = m_firstFrame ? 0 : item->GetHeight();
        if( !pinned ) normalOffset += h;
        else if( toBottom ) bottomOffset += h;
        else topOffset += h;
    }
    m_td.Sync();

    auto draw = ImGui::GetWindowDrawList();
    // Matches the timeline background in normal builds: the root-window build
    // overrides WindowBg per-window, so the fill can be a slightly off shade there.
    const auto bgColor = ImGui::GetColorU32( ImGuiCol_WindowBg );

    // Draws a group at (base + accumulated height) with respect to the
    // first-frame height bootstrap, and returns the total height drawn.
    auto drawRun = [&]( std::vector<TimelineItem*>& items, const TimelineContext& c, int base ) -> int {
        int running = 0;
        for( auto& item : items )
        {
            auto h = item->GetHeight();
            item->Draw( m_firstFrame, c, base + running );
            if( m_firstFrame ) h = item->GetHeight();
            running += h;
        }
        return running;
    };

    const int normalRunning = drawRun( m_normalItems, ctxNormal, pinnedTop );

    // Opaque fills so tracks scrolling under a band do not show through. These also
    // hide parent-list overlays drawn before the child.
    if( pinnedTop > 0 ) draw->AddRectFilled( ImVec2( wpos.x, topBandBegin ), ImVec2( wpos.x + ctx.w, topBandEnd ), bgColor );
    drawRun( m_pinnedTopItems, ctx, curScrollY );
    if( pinnedBottom > 0 ) draw->AddRectFilled( ImVec2( wpos.x, bottomBandBegin ), ImVec2( wpos.x + ctx.w, bottomBandEnd ), bgColor );
    drawRun( m_pinnedBottomItems, ctx, bottomStart );

    int yOffset = pinnedTop + normalRunning + pinnedBottom;

    // pinnedTop is a pre-Draw height, so vertical-centre compensation lags one frame
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
