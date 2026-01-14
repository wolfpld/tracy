#include <assert.h>
#include <stdio.h>

#include "TracyImGui.hpp"
#include "TracyManualData.hpp"
#include "TracyMarkdown.hpp"
#include "TracyView.hpp"

namespace tracy
{

void View::DrawManual()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1200 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "User manual", &m_showManual );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 1.f, 0.f, 1.0f ) );
    ImGui::AlignTextToFramePadding();
    ImGui::TextWrapped( ICON_FA_TRIANGLE_EXCLAMATION );
    ImGui::PopStyleColor();
    ImGui::SameLine();
    TextDisabledUnformatted( "This user manual is missing features. See the PDF file for the proper version." );

    ImGui::Separator();
    ImGui::BeginChild( "##usermanual" );

    ImGui::Columns( 2 );
    static bool widthSet = false;
    if( !widthSet )
    {
        widthSet = true;
        ImGui::SetColumnWidth( 0, 350 * scale );
    }

    ImGui::BeginChild( "##toc", ImVec2( 0, 0 ), ImGuiChildFlags_AlwaysUseWindowPadding );
    int level = 0;
    auto& chunks = m_manualData->GetChunks();
    assert( !chunks.empty() );
    for( size_t i=0; i<chunks.size(); i++ )
    {
        auto& chunk = chunks[i];
        if( chunk.level > level ) continue;

        char tmp[1024];
        if( chunk.section.empty() )
        {
            snprintf( tmp, 1024, "%s", chunk.title.c_str() );
        }
        else
        {
            snprintf( tmp, 1024, "%s. %s", chunk.section.c_str(), chunk.title.c_str() );
        }

        while( level > chunk.level )
        {
            ImGui::TreePop();
            level--;
        }

        ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick | ImGuiTreeNodeFlags_SpanAvailWidth;
        const bool isLeaf = i == ( chunks.size() - 1 ) || chunks[i+1].level <= chunk.level;
        if( isLeaf ) flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
        if( i == m_activeManualChunk ) flags |= ImGuiTreeNodeFlags_Selected;
        if( ImGui::TreeNodeEx( tmp, flags ) )
        {
            if( !isLeaf ) level++;
        }
        if( ImGui::IsItemClicked() && !ImGui::IsItemToggledOpen() )
        {
            m_activeManualChunk = i;
        }
    }
    while( level-- > 0 ) ImGui::TreePop();

    ImGui::EndChild();
    ImGui::NextColumn();
    ImGui::BeginChild( "##content", ImVec2( 0, 0 ), ImGuiChildFlags_AlwaysUseWindowPadding );

    auto& chunk = chunks[m_activeManualChunk];
    m_markdown.Print( chunk.text.c_str(), chunk.text.size() );

    ImGui::EndChild();
    ImGui::EndColumns();
    ImGui::EndChild();
    ImGui::End();
}

}
