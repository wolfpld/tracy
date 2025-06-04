#include <array>
#include <assert.h>

#include "TracyImGui.hpp"
#include "TracyLlmChat.hpp"
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
    RoleData { ICON_FA_ROBOT, ImVec4( 0.4f, 0.5f, 1.f, 1.f ), ImVec4( 1.f, 1.f, 1.f, 1.f ) },
    RoleData { ICON_FA_CODE, ImVec4( 1.0f, 0.5f, 1.f, 1.f ), ImVec4( 1.f, 0.65f, 1.f, 1.f ) },
    RoleData { ICON_FA_CIRCLE_EXCLAMATION, ImVec4( 1.f, 0.25f, 0.25f, 1.f ), ImVec4( 1.f, 0.25f, 0.25f, 1.f ) }
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
}

void TracyLlmChat::End()
{
    if( m_role != TurnRole::None )
    {
        NormalScope();
        ImGui::EndGroup();
    }
}

void TracyLlmChat::Turn( TurnRole role, const std::string& content )
{
    const auto& roleData = roles[(int)role];
    if( role != m_role )
    {
        if( m_role != TurnRole::None )
        {
            NormalScope();
            ImGui::EndGroup();
        }
        m_role = role;
        m_thinkActive = false;
        m_thinkOpen = false;

        const auto diff = m_maxWidth - m_width[(int)role];
        const auto offset = diff / 2;
        ImGui::Spacing();
        ImGui::Dummy( ImVec2( offset, 0 ) );
        ImGui::SameLine( 0, 0 );
        ImGui::TextColored( roleData.iconColor, "%s", roleData.icon );
        ImGui::SameLine( 0, 0 );
        ImGui::Dummy( ImVec2( diff - offset, 0 ) );
        ImGui::SameLine();
        ImGui::BeginGroup();
    }

    ImGui::PushStyleColor( ImGuiCol_Text, roleData.textColor );
    if( role != TurnRole::Assistant )
    {
        ImGui::TextWrapped( "%s", content.c_str() );
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
                    ImGui::PushFont( g_fonts.mono );
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
                PrintMarkdown( content.c_str() + pos, std::min( end, minPos ) - pos );
            }

            pos = minPos;
            if( pos == std::string::npos ) break;

            if( minPos == posThink )
            {
                pos += sizeof( "<think>" ) - 1;
                while( content[pos] == '\n' ) pos++;
                auto endThink = content.find( "</think>", pos );
                ThinkScope();
                if( m_thinkOpen ) PrintThink( content.c_str() + pos, std::min( end, endThink ) - pos );
                if( endThink == std::string::npos ) break;
                pos = endThink + sizeof( "</think>" ) - 1;
                while( content[pos] == '\n' ) pos++;
            }
            else
            {
                assert( minPos == posTool );
                pos += sizeof( "<tool>" ) - 1;
                while( content[pos] == '\n' ) pos++;
                auto endTool = content.find( "</tool>", pos );
                ThinkScope();
                if( m_thinkOpen ) PrintToolCall( content.c_str() + pos, std::min( end, endTool ) - pos );
                if( endTool == std::string::npos ) break;
                pos = endTool + sizeof( "</tool>" ) - 1;
                while( content[pos] == '\n' ) pos++;
            }
        }
    }
    ImGui::PopStyleColor();
}

void TracyLlmChat::NormalScope()
{
    if( !m_thinkActive ) return;
    if( m_thinkOpen )
    {
        ImGui::TreePop();
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

void TracyLlmChat::PrintMarkdown( const char* str, size_t size )
{
    ImGui::TextWrapped( "%.*s", (int)size, str );
}

void TracyLlmChat::PrintThink( const char* str, size_t size )
{
    ImGui::PushStyleColor( ImGuiCol_Text, ThinkColor );
    PrintMarkdown( str, size );
    ImGui::PopStyleColor();
}

void TracyLlmChat::PrintToolCall( const char* str, size_t size )
{
    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.5f, 0.5f, 0.5f, 1.f ) );
    ImGui::PushFont( g_fonts.mono );
    ImGui::TextWrapped( "%.*s", (int)size, str );
    ImGui::PopFont();
    ImGui::PopStyleColor();
}

}
