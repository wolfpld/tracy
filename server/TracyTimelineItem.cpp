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
    , m_offset( 0 )
    , m_view( view )
    , m_worker( worker )
{
}

void TimelineItem::Draw( bool firstFrame, double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    if( !m_visible )
    {
        m_height = 0;
        m_offset = 0;
        return;
    }
    if( IsEmpty() ) return;

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto yPos = AdjustThreadPosition( wpos.y, offset );
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto oldOffset = offset;
    auto draw = ImGui::GetWindowDrawList();

    ImGui::PushID( this );
    ImGui::PushClipRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + m_height ), true );

    float labelWidth;
    const bool drawHeader = yPos + ty >= yMin && yPos <= yMax;
    if( drawHeader )
    {
        const auto color = HeaderColor();
        const auto colorInactive = HeaderColorInactive();

        if( m_showFull )
        {
            DrawTextContrast( draw, wpos + ImVec2( 0, offset ), color, ICON_FA_CARET_DOWN );
        }
        else
        {
            DrawTextContrast( draw, wpos + ImVec2( 0, offset ), colorInactive, ICON_FA_CARET_RIGHT );
        }
        const auto label = HeaderLabel();
        labelWidth = ImGui::CalcTextSize( label ).x;
        DrawTextContrast( draw, wpos + ImVec2( ty, offset ), m_showFull ? color : colorInactive, label );
        DrawLine( draw, dpos + ImVec2( 0, offset + ty - 1 ), dpos + ImVec2( w, offset + ty - 1 ), HeaderLineColor() );

        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + labelWidth, offset + ty ) ) )
        {
            HeaderTooltip( label );

            if( IsMouseClicked( 0 ) )
            {
                m_showFull = !m_showFull;
            }
            if( IsMouseClicked( 2 ) )
            {
                m_view.ZoomToRange( RangeBegin(), RangeEnd() );
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
            m_visible = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    auto hdrOffset = offset;
    offset += ostep;
    if( m_showFull )
    {
        DrawContents( pxns, offset, wpos, hover, yMin, yMax );
        if( drawHeader )
        {
            HeaderExtraContents( hdrOffset, wpos, labelWidth, hover );
        }
    }

    offset += 0.2f * ostep;
    AdjustThreadHeight( firstFrame, oldOffset, offset );

    ImGui::PopClipRect();
    ImGui::PopID();
}

void TimelineItem::AdjustThreadHeight( bool firstFrame, int oldOffset, int& offset )
{
    const auto h = offset - oldOffset;
    if( m_height > h )
    {
        m_height = h;
        offset = oldOffset + m_height;
    }
    else if( m_height < h )
    {
        if( firstFrame )
        {
            m_height = h;
            offset = oldOffset + h;
        }
        else
        {
            const auto diff = h - m_height;
            const auto move = std::max( 2.0, diff * 10.0 * ImGui::GetIO().DeltaTime );
            m_height = int( std::min<double>( m_height + move, h ) );
            offset = oldOffset + m_height;
        }
    }
}

float TimelineItem::AdjustThreadPosition( float wy, int& offset )
{
    if( m_offset < offset )
    {
        m_offset = offset;
    }
    else if( m_offset > offset )
    {
        const auto diff = m_offset - offset;
        const auto move = std::max( 2.0, diff * 10.0 * ImGui::GetIO().DeltaTime );
        offset = m_offset = int( std::max<double>( m_offset - move, offset ) );
    }
    return offset + wy;
}

void TimelineItem::VisibilityCheckbox()
{
    SmallCheckbox( HeaderLabel(), &m_visible );
}

}
