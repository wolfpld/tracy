#include <algorithm>

#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyTimelineItem.hpp"
#include "TracyView.hpp"

namespace tracy
{

TimelineItem::TimelineItem( View& view, Worker& worker )
    : m_visible( true )
    , m_showFull( true )
    , m_height( 0 )
    , m_view( view )
    , m_worker( worker )
{
}

void TimelineItem::Draw( bool firstFrame, double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    if( !IsVisible() )
    {
        if( m_height != 0 ) AdjustThreadHeight( firstFrame, offset, offset );
        return;
    }
    if( IsEmpty() ) return;

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto yPos = wpos.y + offset;
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto oldOffset = offset;
    auto draw = ImGui::GetWindowDrawList();

    ImGui::PushID( this );
    ImGui::PushClipRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + m_height ), true );

    offset += ostep;
    if( m_showFull )
    {
        if( !DrawContents( pxns, offset, wpos, hover, yMin, yMax ) && !m_view.GetViewData().drawEmptyLabels )
        {
            offset = oldOffset;
            AdjustThreadHeight( firstFrame, oldOffset, offset );
            ImGui::PopClipRect();
            ImGui::PopID();
            return;
        }
    }

    DrawOverlay( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ) );
    ImGui::PopClipRect();

    float labelWidth;
    const auto hdrOffset = oldOffset;
    const bool drawHeader = yPos + ty >= yMin && yPos <= yMax;
    if( drawHeader )
    {
        const auto color = HeaderColor();
        const auto colorInactive = HeaderColorInactive();

        if( m_showFull )
        {
            DrawTextContrast( draw, wpos + ImVec2( 0, hdrOffset ), color, ICON_FA_CARET_DOWN );
        }
        else
        {
            DrawTextContrast( draw, wpos + ImVec2( 0, hdrOffset ), colorInactive, ICON_FA_CARET_RIGHT );
        }
        const auto label = HeaderLabel();
        labelWidth = ImGui::CalcTextSize( label ).x;
        DrawTextContrast( draw, wpos + ImVec2( ty, hdrOffset ), m_showFull ? color : colorInactive, label );
        if( m_showFull )
        {
            DrawLine( draw, dpos + ImVec2( 0, hdrOffset + ty - 1 ), dpos + ImVec2( w, hdrOffset + ty - 1 ), HeaderLineColor() );
            HeaderExtraContents( hdrOffset, wpos, labelWidth, pxns, hover );
        }

        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, hdrOffset ), wpos + ImVec2( ty + labelWidth, hdrOffset + ty ) ) )
        {
            HeaderTooltip( label );

            if( IsMouseClicked( 0 ) )
            {
                m_showFull = !m_showFull;
            }
            if( IsMouseClicked( 2 ) )
            {
                const auto t0 = RangeBegin();
                const auto t1 = RangeEnd();
                if( t0 < t1 )
                {
                    m_view.ZoomToRange( t0, t1 );
                }
            }
            if( IsMouseClicked( 1 ) )
            {
                ImGui::OpenPopup( "menuPopup" );
            }
        }
    }

    if( ImGui::BeginPopup( "menuPopup" ) )
    {
        if( ImGui::MenuItem( ICON_FA_EYE_SLASH " Hide" ) )
        {
            SetVisible( false );
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    offset += 0.2f * ostep;
    AdjustThreadHeight( firstFrame, oldOffset, offset );

    ImGui::PopID();
}

void TimelineItem::AdjustThreadHeight( bool firstFrame, int oldOffset, int& offset )
{
    const auto speed = 4.0;
    const auto baseMove = 1.0;

    const auto h = offset - oldOffset;
    if( firstFrame )
    {
        m_height = h;
    }
    else if( m_height != h )
    {
        const auto diff = h - m_height;
        const auto preClampMove = diff * speed * ImGui::GetIO().DeltaTime;
        if( diff > 0 )
        {
            const auto move = preClampMove + baseMove;
            m_height = int( std::min<double>( m_height + move, h ) );
        }
        else
        {
            const auto move = preClampMove - baseMove;
            m_height = int( std::max<double>( m_height + move, h ) );
        }
        s_wasActive = true;
    }
    offset = oldOffset + m_height;
}

void TimelineItem::VisibilityCheckbox()
{
    SmallCheckbox( HeaderLabel(), &m_visible );
}

}
