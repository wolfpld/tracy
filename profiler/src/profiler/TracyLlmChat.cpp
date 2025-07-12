#include <array>
#include <assert.h>
#include <md4c.h>
#include <nlohmann/json.hpp>
#include <string>

#include "TracyImGui.hpp"
#include "TracyLlmChat.hpp"
#include "TracyMouse.hpp"
#include "../Fonts.hpp"

namespace tracy
{

constexpr auto ThinkColor = ImVec4( 0.5f, 0.5f, 0.3f, 1.f );

struct RoleData
{
    const char* icon;
    ImVec4 iconColor;
    ImVec4 textColor;
};

constexpr std::array roles = {
    RoleData { ICON_FA_USER, ImVec4( 0.75f, 1.f, 0.25f, 1.f ), ImVec4( 0.64f, 0.76f, 0.41f, 1.f ) },
    RoleData { ICON_FA_TERMINAL, ImVec4( 1.f, 0.5f, 0.5f, 1.f ), ImVec4( 1.f, 0.65f, 0.65f, 1.f ) },
    RoleData { ICON_FA_FILE, ImVec4( 0.5f, 0.75f, 1.f, 1.f ), ImVec4( 0.65f, 0.75f, 1.f, 1.f ) },
    RoleData { ICON_FA_ROBOT, ImVec4( 0.4f, 0.5f, 1.f, 1.f ), ImVec4( 1.f, 1.f, 1.f, 1.f ) },
    RoleData { ICON_FA_CODE, ImVec4( 1.0f, 0.5f, 1.f, 1.f ), ImVec4( 1.f, 0.65f, 1.f, 1.f ) },
    RoleData { ICON_FA_CIRCLE_EXCLAMATION, ImVec4( 1.f, 0.25f, 0.25f, 1.f ), ImVec4( 1.f, 0.25f, 0.25f, 1.f ) },
    RoleData { ICON_FA_TRASH, ImVec4( 1.0f, 0.25f, 0.25f, 1.f ), ImVec4( 1.f, 1.f, 1.f, 1.f ) },
    RoleData { ICON_FA_ARROWS_ROTATE, ImVec4( 1.0f, 0.25f, 0.25f, 1.f ), ImVec4( 1.f, 1.f, 1.f, 1.f ) },
};
constexpr size_t NumRoles = roles.size();

static_assert( NumRoles == (int)TracyLlmChat::TurnRole::None );


TracyLlmChat::TracyLlmChat()
    : m_width( new float[NumRoles] )
{
}

TracyLlmChat::~TracyLlmChat()
{
    delete[] m_width;
}

void TracyLlmChat::Begin()
{
    float max = 0;
    for( size_t i=0; i<NumRoles; ++i )
    {
        m_width[i] = ImGui::CalcTextSize( roles[i].icon ).x;
        max = std::max( max, m_width[i] );
    }
    m_maxWidth = max;

    m_role = TurnRole::None;
    m_thinkActive = false;
    m_thinkOpen = false;
    m_thinkIdx = 0;
    m_subIdx = 0;
    m_roleIdx = 0;
}

void TracyLlmChat::End()
{
    if( m_role != TurnRole::None )
    {
        NormalScope();
        ImGui::EndGroup();
        ImGui::PopID();
    }
}

bool TracyLlmChat::Turn( TurnRole role, const std::string& content )
{
    bool keep = true;
    const auto& roleData = roles[(int)role];
    if( role != m_role || role == TurnRole::Attachment || role == TurnRole::Error )
    {
        if( m_role != TurnRole::None )
        {
            NormalScope();
            ImGui::EndGroup();
            ImGui::PopID();
        }
        m_thinkActive = false;
        m_thinkOpen = false;

        bool hover = false;
        if( m_role != role )
        {
            m_role = role;
            ImGui::Spacing();
        }
        int trashIdx = ( role == TurnRole::Assistant || role == TurnRole::AssistantDebug ) ? (int)TurnRole::Regenerate : (int)TurnRole::Trash;
        ImGui::PushID( m_roleIdx++ );
        auto diff = m_maxWidth - m_width[(int)role];
        if( ImGui::IsMouseHoveringRect( ImGui::GetCursorScreenPos(), ImGui::GetCursorScreenPos() + ImVec2( m_maxWidth, ImGui::GetTextLineHeight() ) ) )
        {
            diff = m_maxWidth - m_width[trashIdx];
            hover = true;
        }
        const auto offset = diff / 2;
        ImGui::Dummy( ImVec2( offset, 0 ) );
        ImGui::SameLine( 0, 0 );
        if( hover )
        {
            const auto& trash = roles[trashIdx];
            ImGui::TextColored( trash.iconColor, "%s", trash.icon );
            if( IsMouseClicked( ImGuiMouseButton_Left ) ) keep = false;
        }
        else
        {
            ImGui::TextColored( roleData.iconColor, "%s", roleData.icon );
        }
        ImGui::SameLine( 0, 0 );
        ImGui::Dummy( ImVec2( diff - offset, 0 ) );
        ImGui::SameLine();
        ImGui::BeginGroup();
    }

    const auto posStart = ImGui::GetCursorScreenPos();
    ImGui::PushStyleColor( ImGuiCol_Text, roleData.textColor );
    if( role == TurnRole::Error )
    {
        ImGui::PushFont( g_fonts.mono, FontNormal );
        ImGui::TextWrapped( "%s", content.c_str() );
        ImGui::PopFont();
    }
    else if( role == TurnRole::Attachment )
    {
        constexpr auto tagSize = sizeof( "<attachment>\n" ) - 1;

        auto j = nlohmann::json::parse( content.c_str() + tagSize, content.c_str() + content.size() );
        const auto& type = j["type"].get_ref<const std::string&>();

        NormalScope();
        ImGui::PushID( m_thinkIdx++ );
        const bool expand = ImGui::TreeNode( "Attachment" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", type.c_str() );
        if( expand )
        {
            ImGui::PushFont( g_fonts.mono, FontNormal );
            ImGui::TextWrapped( "%s", content.c_str() + tagSize );
            ImGui::PopFont();
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
    else if( role != TurnRole::Assistant )
    {
        m_markdown.Print( content.c_str(), content.size() );
    }
    else if( content.starts_with( "<tool_output>\n" ) )
    {
        ThinkScope();
        if( m_thinkOpen )
        {
            ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.5f, 0.5f, 0.5f, 1.f ) );
            if( content == ForgetMsg )
            {
                ImGui::TextUnformatted( ICON_FA_RECYCLE " Tool response removed to save context space" );
                m_subIdx++;
            }
            else
            {
                ImGui::PushID( m_subIdx++ );
                if( ImGui::TreeNode( ICON_FA_REPLY " Tool response..." ) )
                {
                    ImGui::PushFont( g_fonts.mono, FontNormal );
                    ImGui::TextWrapped( "%s", content.c_str() + sizeof( "<tool_output>\n" ) - 1 );
                    ImGui::PopFont();
                    ImGui::TreePop();
                }
                ImGui::PopID();
            }
            ImGui::PopStyleColor();
        }
        else
        {
            m_subIdx++;
        }
    }
    else
    {
        size_t pos = 0;
        size_t end = content.size();
        while( pos < end )
        {
            auto posThink = content.find( "<think>", pos );
            auto posTool = content.find( "<tool>", pos );
            auto minPos = std::min( posThink, posTool );

            if( pos != minPos )
            {
                NormalScope();
                m_markdown.Print( content.c_str() + pos, std::min( end, minPos ) - pos );
            }

            pos = minPos;
            if( pos == std::string::npos ) break;

            if( minPos == posThink )
            {
                pos += sizeof( "<think>" ) - 1;
                while( content[pos] == '\n' || content[pos] == ' ' ) pos++;
                auto endThink = content.find( "</think>", pos );
                if( endThink != pos )
                {
                    ThinkScope();
                    if( m_thinkOpen ) PrintThink( content.c_str() + pos, std::min( end, endThink ) - pos );
                }
                if( endThink == std::string::npos ) break;
                pos = endThink;
                do
                {
                    pos += sizeof( "</think>" ) - 1;
                    while( content[pos] == '\n' || content[pos] == ' ' ) pos++;
                }
                while( strncmp( content.c_str() + pos, "</think>", sizeof( "</think>" ) - 1 ) == 0 );
            }
            else
            {
                assert( minPos == posTool );
                pos += sizeof( "<tool>" ) - 1;
                while( content[pos] == '\n' || content[pos] == ' ' ) pos++;
                auto endTool = content.find( "</tool>", pos );
                ThinkScope();
                if( m_thinkOpen ) PrintToolCall( content.c_str() + pos, std::min( end, endTool ) - pos );
                if( endTool == std::string::npos ) break;
                pos = endTool + sizeof( "</tool>" ) - 1;
                while( content[pos] == '\n' || content[pos] == ' ' ) pos++;
            }
        }
    }
    ImGui::PopStyleColor();

    if( ImGui::IsMouseClicked( ImGuiMouseButton_Right ) &&
        ImGui::IsWindowHovered() &&
        ImGui::IsMouseHoveringRect( posStart, ImGui::GetCursorScreenPos() + ImVec2( ImGui::GetContentRegionAvail().x, 0 ) ) )
    {
        ImGui::OpenPopup( "ContextMenu" );
    }
    if( ImGui::BeginPopup( "ContextMenu" ) )
    {
        if( ImGui::Selectable( ICON_FA_CLIPBOARD " Copy" ) )
        {
            ImGui::SetClipboardText( content.c_str() );
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    return keep;
}

void TracyLlmChat::NormalScope()
{
    if( !m_thinkActive ) return;
    if( m_thinkOpen )
    {
        ImGui::TreePop();
        ImGui::Spacing();
        m_thinkOpen = false;
    }
    ImGui::PopStyleColor();
    ImGui::PopID();
    m_thinkActive = false;
}

void TracyLlmChat::ThinkScope()
{
    if( m_thinkActive ) return;
    m_thinkActive = true;
    ImGui::PushID( m_thinkIdx++ );
    ImGui::PushStyleColor( ImGuiCol_Text, ThinkColor );
    m_thinkOpen = ImGui::TreeNode( ICON_FA_LIGHTBULB " Internal thoughts..." );
}

void TracyLlmChat::PrintThink( const char* str, size_t size )
{
    ImGui::PushStyleColor( ImGuiCol_Text, ThinkColor );
    m_markdown.Print( str, size );
    ImGui::PopStyleColor();
}

void TracyLlmChat::PrintToolCall( const char* str, size_t size )
{
    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.5f, 0.5f, 0.5f, 1.f ) );
    ImGui::PushFont( g_fonts.mono, FontNormal );
    ImGui::TextWrapped( "%.*s", (int)size, str );
    ImGui::PopFont();
    ImGui::PopStyleColor();
}

}
