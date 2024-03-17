#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

void View::DrawRanges()
{
    ImGui::Begin( "Time range limits", &m_showRanges, ImGuiWindowFlags_AlwaysAutoResize );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
    DrawRangeEntry( m_findZone.range, ICON_FA_MAGNIFYING_GLASS " Find zone", 0x4488DD88, "RangeFindZoneCopyFrom", 0 );
    ImGui::Separator();
    DrawRangeEntry( m_statRange, ICON_FA_ARROW_UP_WIDE_SHORT " Statistics", 0x448888EE, "RangeStatisticsCopyFrom", 1 );
    ImGui::Separator();
    DrawRangeEntry( m_waitStackRange, ICON_FA_HOURGLASS_HALF " Wait stacks", 0x44EEB588, "RangeWaitStackCopyFrom", 2 );
    ImGui::Separator();
    DrawRangeEntry( m_memInfo.range, ICON_FA_MEMORY " Memory", 0x4488EEE3, "RangeMemoryCopyFrom", 3 );
    ImGui::End();
}

void View::DrawRangeEntry( Range& range, const char* label, uint32_t color, const char* popupLabel, int id )
{
    SmallColorBox( color );
    ImGui::SameLine();
    if( SmallCheckbox( label, &range.active ) )
    {
        if( range.active && range.min == 0 && range.max == 0 )
        {
            range.min = m_vd.zvStart;
            range.max = m_vd.zvEnd;
        }
    }
    if( range.active )
    {
        ImGui::SameLine();
        if( ImGui::SmallButton( "Limit to view" ) )
        {
            range.min = m_vd.zvStart;
            range.max = m_vd.zvEnd;
        }
        TextFocused( "Time range:", TimeToStringExact( range.min ) );
        ImGui::SameLine();
        TextFocused( "-", TimeToStringExact( range.max ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", TimeToString( range.max - range.min ) );
        if( ImGui::SmallButton( ICON_FA_MICROSCOPE " Focus" ) ) ZoomToRange( range.min, range.max );
        ImGui::SameLine();
        if( SmallButtonDisablable( ICON_FA_NOTE_STICKY " Set from annotation", m_annotations.empty() ) ) ImGui::OpenPopup( popupLabel );
        if( ImGui::BeginPopup( popupLabel ) )
        {
            for( auto& v : m_annotations )
            {
                SmallColorBox( v->color );
                ImGui::SameLine();
                if( ImGui::Selectable( v->text.c_str() ) )
                {
                    range.min = v->range.min;
                    range.max = v->range.max;
                }
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                ImGui::TextDisabled( "%s - %s (%s)", TimeToStringExact( v->range.min ), TimeToStringExact( v->range.max ), TimeToString( v->range.max - v->range.min ) );
            }
            ImGui::EndPopup();
        }
        if( id != 0 )
        {
            ImGui::SameLine();
            if( SmallButtonDisablable( ICON_FA_MAGNIFYING_GLASS " Copy from find zone", m_findZone.range.min == 0 && m_findZone.range.max == 0 ) ) range = m_findZone.range;
        }
        if( id != 1 )
        {
            ImGui::SameLine();
            if( SmallButtonDisablable( ICON_FA_ARROW_UP_WIDE_SHORT " Copy from statistics", m_statRange.min == 0 && m_statRange.max == 0 ) ) range = m_statRange;
        }
        if( id != 2 )
        {
            ImGui::SameLine();
            if( SmallButtonDisablable( ICON_FA_HOURGLASS_HALF " Copy from wait stacks", m_waitStackRange.min == 0 && m_waitStackRange.max == 0 ) ) range = m_waitStackRange;
        }
        if( id != 3 )
        {
            ImGui::SameLine();
            if( SmallButtonDisablable( ICON_FA_MEMORY " Copy from memory", m_memInfo.range.min == 0 && m_memInfo.range.max == 0 ) ) range = m_memInfo.range;
        }
    }
}

void View::HandleRange( Range& range, int64_t timespan, const ImVec2& wpos, float w )
{
    if( !IsMouseDown( 0 ) ) range.modMin = range.modMax = false;
    if( !range.active ) return;
    auto& io = ImGui::GetIO();

    if( range.modMin )
    {
        const auto nspx = double( timespan ) / w;
        range.min = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
        range.hiMin = true;
        ConsumeMouseEvents( 0 );
        ImGui::SetMouseCursor( ImGuiMouseCursor_ResizeEW );
        if( range.min > range.max )
        {
            std::swap( range.min, range.max );
            std::swap( range.hiMin, range.hiMax );
            std::swap( range.modMin, range.modMax );
        }
    }
    else if( range.modMax )
    {
        const auto nspx = double( timespan ) / w;
        range.max = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
        range.hiMax = true;
        ConsumeMouseEvents( 0 );
        ImGui::SetMouseCursor( ImGuiMouseCursor_ResizeEW );
        if( range.min > range.max )
        {
            std::swap( range.min, range.max );
            std::swap( range.hiMin, range.hiMax );
            std::swap( range.modMin, range.modMax );
        }
    }
    else
    {
        const auto pxns = w / double( timespan );
        const auto px0 = ( range.min - m_vd.zvStart ) * pxns;
        if( abs( px0 - ( io.MousePos.x - wpos.x ) ) < 3 )
        {
            range.hiMin = true;
            ImGui::SetMouseCursor( ImGuiMouseCursor_ResizeEW );
            if( IsMouseClicked( 0 ) )
            {
                range.modMin = true;
                range.min = m_vd.zvStart + ( io.MousePos.x - wpos.x ) / pxns;
                ConsumeMouseEvents( 0 );
                if( range.min > range.max )
                {
                    std::swap( range.min, range.max );
                    std::swap( range.hiMin, range.hiMax );
                    std::swap( range.modMin, range.modMax );
                }
            }
        }
        else
        {
            const auto px1 = ( range.max - m_vd.zvStart ) * pxns;
            if( abs( px1 - ( io.MousePos.x - wpos.x ) ) < 3 )
            {
                range.hiMax = true;
                ImGui::SetMouseCursor( ImGuiMouseCursor_ResizeEW );
                if( IsMouseClicked( 0 ) )
                {
                    range.modMax = true;
                    range.max = m_vd.zvStart + ( io.MousePos.x - wpos.x ) / pxns;
                    ConsumeMouseEvents( 0 );
                    if( range.min > range.max )
                    {
                        std::swap( range.min, range.max );
                        std::swap( range.hiMin, range.hiMax );
                        std::swap( range.modMin, range.modMax );
                    }
                }
            }
        }
    }
}

}
