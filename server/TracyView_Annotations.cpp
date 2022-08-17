#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

void View::AddAnnotation( int64_t start, int64_t end )
{
    auto ann = std::make_unique<Annotation>();
    ann->range.active = true;
    ann->range.min = start;
    ann->range.max = end;
    ann->color = 0x888888;
    m_selectedAnnotation = ann.get();
    m_annotations.emplace_back( std::move( ann ) );
    pdqsort_branchless( m_annotations.begin(), m_annotations.end(), []( const auto& lhs, const auto& rhs ) { return lhs->range.min < rhs->range.min; } );
}

void View::DrawSelectedAnnotation()
{
    assert( m_selectedAnnotation );
    bool show = true;
    ImGui::Begin( "Annotation", &show, ImGuiWindowFlags_AlwaysAutoResize );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to annotation" ) )
        {
            ZoomToRange( m_selectedAnnotation->range.min, m_selectedAnnotation->range.max );
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_TRASH_CAN " Remove" ) )
        {
            for( auto it = m_annotations.begin(); it != m_annotations.end(); ++it )
            {
                if( it->get() == m_selectedAnnotation )
                {
                    m_annotations.erase( it );
                    break;
                }
            }
            ImGui::End();
            m_selectedAnnotation = nullptr;
            return;
        }
        ImGui::Separator();
        {
            const auto desc = m_selectedAnnotation->text.c_str();
            const auto descsz = std::min<size_t>( 1023, m_selectedAnnotation->text.size() );
            char buf[1024];
            buf[descsz] = '\0';
            memcpy( buf, desc, descsz );
            if( ImGui::InputTextWithHint( "##anndesc", "Describe annotation", buf, 256 ) )
            {
                m_selectedAnnotation->text.assign( buf );
            }
        }
        ImVec4 col = ImGui::ColorConvertU32ToFloat4( m_selectedAnnotation->color );
        ImGui::ColorEdit3( "Color", &col.x );
        m_selectedAnnotation->color = ImGui::ColorConvertFloat4ToU32( col );
        ImGui::Separator();
        TextFocused( "Annotation begin:", TimeToStringExact( m_selectedAnnotation->range.min ) );
        TextFocused( "Annotation end:", TimeToStringExact( m_selectedAnnotation->range.max ) );
        TextFocused( "Annotation length:", TimeToString( m_selectedAnnotation->range.max - m_selectedAnnotation->range.min ) );
    }
    ImGui::End();
    if( !show ) m_selectedAnnotation = nullptr;
}

void View::DrawAnnotationList()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 600 * scale, 300 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Annotation list", &m_showAnnotationList );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    if( ImGui::Button( ICON_FA_PLUS " Add annotation" ) )
    {
        AddAnnotation( m_vd.zvStart, m_vd.zvEnd );
    }

    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();

    if( m_annotations.empty() )
    {
        ImGui::TextWrapped( "No annotations." );
        ImGui::Separator();
        ImGui::End();
        return;
    }

    TextFocused( "Annotations:", RealToString( m_annotations.size() ) );
    ImGui::Separator();
    ImGui::BeginChild( "##annotationList" );
    const bool ctrl = ImGui::GetIO().KeyCtrl;
    int remove = -1;
    int idx = 0;
    for( auto& ann : m_annotations )
    {
        ImGui::PushID( idx );
        if( ImGui::Button( ICON_FA_PEN_TO_SQUARE ) )
        {
            m_selectedAnnotation = ann.get();
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_MICROSCOPE ) )
        {
            ZoomToRange( ann->range.min, ann->range.max );
        }
        ImGui::SameLine();
        if( ButtonDisablable( ICON_FA_TRASH_CAN, !ctrl ) )
        {
            remove = idx;
        }
        if( !ctrl ) TooltipIfHovered( "Press ctrl key to enable removal" );
        ImGui::SameLine();
        ImGui::ColorButton( "c", ImGui::ColorConvertU32ToFloat4( ann->color ), ImGuiColorEditFlags_NoTooltip );
        ImGui::SameLine();
        if( m_selectedAnnotation == ann.get() )
        {
            bool t = true;
            ImGui::Selectable( "##annSelectable", &t );
            ImGui::SameLine( 0, 0 );
        }
        if( ann->text.empty() )
        {
            TextDisabledUnformatted( "Empty annotation" );
        }
        else
        {
            ImGui::TextUnformatted( ann->text.c_str() );
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::TextDisabled( "%s - %s (%s)", TimeToStringExact( ann->range.min ), TimeToStringExact( ann->range.max ), TimeToString( ann->range.max - ann->range.min ) );
        ImGui::PopID();
        idx++;
    }
    if( remove >= 0 )
    {
        if( m_annotations[remove].get() == m_selectedAnnotation ) m_selectedAnnotation = nullptr;
        m_annotations.erase( m_annotations.begin() + remove );
    }
    ImGui::EndChild();
    ImGui::End();
}

}
