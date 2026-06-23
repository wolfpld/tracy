#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

void View::SetupRanges()
{
    m_ranges = {{
        { &m_findZone.range, 0x88DD88, ICON_FA_MAGNIFYING_GLASS " Find zone" },
        { &m_statRange,      0x8888EE, ICON_FA_ARROW_UP_WIDE_SHORT " Statistics" },
        { &m_flameRange,     0x88B5EE, ICON_FA_FIRE_FLAME_CURVED " Flame graph" },
        { &m_waitStackRange, 0xEEB588, ICON_FA_HOURGLASS_HALF " Wait stacks" },
        { &m_memInfo.range,  0x88EEE3, ICON_FA_MEMORY " Memory" },
    }};
}

void View::DrawRanges()
{
    ImGui::Begin( "Time range limits", &m_showRanges, ImGuiWindowFlags_AlwaysAutoResize );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    int idx = 0;
    bool first = true;
    for( auto& r : m_ranges )
    {
        if( first ) first = false;
        else ImGui::Separator();
        DrawRangeEntry( *r.range, r.name, r.color, idx++ );
    }
    ImGui::End();
}

void View::DrawRangeEntry( Range& range, const char* label, uint32_t color, int id )
{
    ImGui::PushID( id );
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
        TextFocused( ICON_FA_STOPWATCH " Time range:", TimeToStringExact( range.min ) );
        ImGui::SameLine();
        TextFocused( "-", TimeToStringExact( range.max ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", TimeToString( range.max - range.min ) );
        ImGui::SameLine();
        if( ImGui::SmallButton( ICON_FA_MICROSCOPE " Focus" ) ) ZoomToRange( range.min, range.max );
        ImGui::TextDisabled( ICON_FA_COPY " Copy from:" );
        ImGui::SameLine();
        if( SmallButtonDisablable( ICON_FA_NOTE_STICKY " Annotation", m_annotations.empty() ) ) ImGui::OpenPopup( label );
        if( ImGui::BeginPopup( label ) )
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
        int idx = 0;
        for( auto& r : m_ranges )
        {
            if( idx++ == id ) continue;
            ImGui::SameLine();
            if( SmallButtonDisablable( r.name, r.range->min == 0 && r.range->max == 0 ) ) range = *r.range;
        }
    }
    ImGui::PopID();
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
