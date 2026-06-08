#include <assert.h>
#include <stdio.h>

#include "TracyImGui.hpp"
#include "TracyManualData.hpp"
#include "TracyMarkdown.hpp"
#include "TracyView.hpp"
#include "TracyWeb.hpp"
#include "../Fonts.hpp"

namespace tracy
{

void View::DrawManual()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1200 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    if( m_manualPositionReset ) ImGui::SetNextWindowFocus();
    ImGui::Begin( "User manual", &m_showManual );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 1.f, 0.f, 1.0f ) );
    ImGui::AlignTextToFramePadding();
    ImGui::TextWrapped( ICON_FA_TRIANGLE_EXCLAMATION );
    ImGui::PopStyleColor();
    ImGui::SameLine();
    TextDisabledUnformatted( "This user manual is missing features. See the PDF file for the proper version." );
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_BOOK " PDF Manual" ) ) OpenWebpage( "https://github.com/wolfpld/tracy/releases" );

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

        if( m_manualPositionReset && i < m_activeManualChunk && chunk.level < chunks[m_activeManualChunk].level )
        {
            bool ancestor = true;
            for( size_t j = i+1; j < m_activeManualChunk; j++ )
            {
                if( chunks[j].level <= chunk.level )
                {
                    ancestor = false;
                    break;
                }
            }
            if( ancestor ) ImGui::SetNextItemOpen( true, ImGuiCond_Always );
        }

        ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick | ImGuiTreeNodeFlags_SpanAvailWidth;
        const bool isLeaf = i == ( chunks.size() - 1 ) || chunks[i+1].level <= chunk.level;
        if( isLeaf ) flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
        if( i == m_activeManualChunk ) flags |= ImGuiTreeNodeFlags_Selected;
        if( ImGui::TreeNodeEx( tmp, flags ) )
        {
            if( !isLeaf ) level++;
        }
        if( m_manualPositionReset && i == m_activeManualChunk ) ImGui::SetScrollHereY();
        if( ImGui::IsItemClicked() && !ImGui::IsItemToggledOpen() )
        {
            m_activeManualChunk = i;
            m_manualPositionReset = true;
        }
    }
    while( level-- > 0 ) ImGui::TreePop();

    ImGui::EndChild();
    ImGui::NextColumn();
    ImGui::BeginChild( "##content", ImVec2( 0, 0 ), ImGuiChildFlags_AlwaysUseWindowPadding );

    if( m_manualPositionReset )
    {
        ImGui::SetScrollY( 0 );
        m_manualPositionReset = false;
    }

    auto& chunk = chunks[m_activeManualChunk];

    if( m_activeManualChunk == 0 )
    {
        ImageCentered( GetProfilerIconTexture(), ImVec2( 80 * scale, 80 * scale ) );
        ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.5f ) );
        ImGui::PushFont( g_fonts.bold, FontNormal * 2.f );
        TextCentered( "Tracy Profiler" );
        ImGui::PopFont();
        ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.25f ) );
        ImGui::PushFont( g_fonts.normal, FontNormal * 1.25f );
        TextCentered( "The user manual" );
        ImGui::PopFont();
        ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 2 ) );
        TextCentered( "Bartosz Taudul <wolf@nereid.pl>" );
        ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.5f ) );
        TextCentered( "https://github.com/wolfpld/tracy" );
        if( ImGui::IsItemHovered() )
        {
            ImGui::SetMouseCursor( ImGuiMouseCursor_Hand );
            if( ImGui::IsItemClicked() )
            {
                OpenWebpage( "https://github.com/wolfpld/tracy" );
            }
        }
    }
    else
    {
        ImGui::PushFont( g_fonts.normal, FontBig );
        if( chunk.section.empty() )
        {
            ImGui::TextUnformatted( chunk.title.c_str() );
        }
        else
        {
            ImGui::Text( "%s. %s", chunk.section.c_str(), chunk.title.c_str() );
        }
        ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.25f ) );
        ImGui::PopFont();

        const auto separator = chunk.text.find( "\n-----" );
        const auto size = separator == std::string::npos ? chunk.text.size() : ( separator + 1 );

        m_markdown.Print( chunk.text.c_str(), size );
    }

    ImGui::EndChild();
    ImGui::EndColumns();
    ImGui::EndChild();
    ImGui::End();
}

const TracyManualData::ManualChunk* View::GetManualChunk( const char* anchor ) const
{
    assert( anchor && *anchor );
    assert( m_manualData );

    auto& chunks = m_manualData->GetChunks();
    auto it = std::ranges::find_if( chunks, [anchor]( const auto& chunk ) { return chunk.link == anchor; } );
    if( it != chunks.end() ) return &*it;
    return nullptr;
}

bool View::ViewManualChunk( const char* anchor )
{
    assert( anchor && *anchor );
    const auto chunk = GetManualChunk( anchor );
    if( !chunk ) return false;
    m_activeManualChunk = std::distance( m_manualData->GetChunks().data(), chunk );
    m_showManual = true;
    m_manualPositionReset = true;
    return true;
}

}
