#include <array>
#include <assert.h>
#include <md4c.h>
#include <string>
#include <string.h>
#include <vector>

#include "TracyImGui.hpp"
#include "TracyLlmChat.hpp"
#include "TracyMouse.hpp"
#include "TracyWeb.hpp"
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
};
constexpr size_t NumRoles = roles.size();

static_assert( NumRoles == (int)TracyLlmChat::TurnRole::None );


class Markdown
{
    struct List
    {
        bool tight;
        int num;
    };

public:
    int EnterBlock( MD_BLOCKTYPE type, void* detail )
    {
        switch( type )
        {
        case MD_BLOCK_P:
            Separate();
            glue = false;
            break;
        case MD_BLOCK_QUOTE:
            Separate();
            ImGui::Indent();
            break;
        case MD_BLOCK_UL:
            Separate();
            lists.emplace_back( List {
                .tight = ((MD_BLOCK_UL_DETAIL*)detail)->is_tight != 0,
                .num = -1
            } );
            ImGui::Indent();
            break;
        case MD_BLOCK_OL:
            Separate();
            lists.emplace_back( List {
                .tight = ((MD_BLOCK_OL_DETAIL*)detail)->is_tight != 0,
                .num = (int)((MD_BLOCK_OL_DETAIL*)detail)->start
            } );
            ImGui::Indent();
            break;
        case MD_BLOCK_LI:
        {
            Separate();
            auto& l = lists.back();
            if( l.num < 0 )
            {
                ImGui::Bullet();
            }
            else
            {
                ImGui::Text( "%d.", l.num++ );
            }
            glue = false;
            ImGui::SameLine();
            ImGui::BeginGroup();
            break;
        }
        case MD_BLOCK_HR:
            Separate();
            ImGui::Separator();
            break;
        case MD_BLOCK_H:
            Separate();
            header = ((MD_BLOCK_H_DETAIL*)detail)->level;
            break;
        case MD_BLOCK_CODE:
        {
            char tmp[64];
            sprintf( tmp, "##code%d", idx++ );
            Separate();
            ImGui::BeginChild( tmp, ImVec2( 0, 0 ), ImGuiChildFlags_FrameStyle | ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY );
        }
        default:
            break;
        }
        return 0;
    }

    int LeaveBlock( MD_BLOCKTYPE type, void* detail )
    {
        switch( type )
        {
        case MD_BLOCK_P:
            separate = true;
            break;
        case MD_BLOCK_QUOTE:
            ImGui::Unindent();
            separate = true;
        case MD_BLOCK_UL:
        case MD_BLOCK_OL:
            ImGui::Unindent();
            if( !lists.empty() ) lists.pop_back();
            separate = lists.empty() || !lists.back().tight;
            break;
        case MD_BLOCK_LI:
        {
            ImGui::EndGroup();
            auto& l = lists.back();
            if( !l.tight ) separate = true;
            break;
        }
        case MD_BLOCK_HR:
            separate = true;
            break;
        case MD_BLOCK_H:
            header = 0;
            separate = true;
            break;
        case MD_BLOCK_CODE:
            ImGui::EndChild();
            separate = true;
            break;
        default:
            break;
        }
        return 0;
    }

    int EnterSpan( MD_SPANTYPE type, void* detail )
    {
        switch( type )
        {
        case MD_SPAN_EM:
            italic++;
            break;
        case MD_SPAN_STRONG:
            bold++;
            break;
        case MD_SPAN_A:
            link = std::string( ((MD_SPAN_A_DETAIL*)detail)->href.text, ((MD_SPAN_A_DETAIL*)detail)->href.size );
            break;
        default:
            break;
        }
        return 0;
    }

    int LeaveSpan( MD_SPANTYPE type, void* detail )
    {
        switch( type )
        {
        case MD_SPAN_EM:
            italic--;
            break;
        case MD_SPAN_STRONG:
            bold--;
            break;
        case MD_SPAN_A:
            link.clear();
            break;
        default:
            break;
        }
        return 0;
    }

    int Text( MD_TEXTTYPE type, const MD_CHAR* text, MD_SIZE size )
    {
        switch( type )
        {
        case MD_TEXT_NORMAL:
        case MD_TEXT_ENTITY:
        case MD_TEXT_HTML:
        {
            if( header > 0 )
            {
                ImGui::PushFont( g_fonts.big );
            }
            else if( bold > 0 )
            {
                ImGui::PushFont( italic > 0 ? g_fonts.boldItalic : g_fonts.bold );
            }
            else if( italic > 0 )
            {
                ImGui::PushFont( g_fonts.italic );
            }
            if( !link.empty() ) ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.55f, 0.55f, 1.f, 1.f ) );
            Glue();
            const auto hovered = PrintTextWrapped( text, text + size );
            if( !link.empty() )
            {
                ImGui::PopStyleColor();
                if( hovered )
                {
                    ImGui::SetMouseCursor( ImGuiMouseCursor_Hand );
                    ImGui::BeginTooltip();
                    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 1.f, 1.f, 1.f ) );
                    ImGui::TextUnformatted( link.c_str() );
                    ImGui::PopStyleColor();
                    ImGui::EndTooltip();
                    if( IsMouseClicked( ImGuiMouseButton_Left ) ) OpenWebpage( link.c_str() );
                }
            }
            if( header > 0 || bold > 0 || italic > 0 ) ImGui::PopFont();
            break;
        }
        case MD_TEXT_NULLCHAR:
            Glue();
            PrintTextWrapped( "\xEF\xBF\xBD" );
            break;
        case MD_TEXT_BR:
            glue = false;
            break;
        case MD_TEXT_SOFTBR:
            Glue();
            PrintTextWrapped( " " );
            break;
        case MD_TEXT_CODE:
        case MD_TEXT_LATEXMATH:
            if( size == 1 && *text == '\n' )
            {
                glue = false;
            }
            else
            {
                Glue();
                ImGui::PushFont( g_fonts.mono );
                PrintTextWrapped( text, text + size );
                ImGui::PopFont();
            }
            break;
        }
        return 0;
    }

private:
    void Glue()
    {
        if( glue ) ImGui::SameLine( 0, 0 );
        else glue = true;
    }

    void Separate()
    {
        if( !separate ) return;
        ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.5f ) );
        separate = false;
    }

    int bold = 0;
    int italic = 0;
    int header = 0;

    bool glue = false;
    bool separate = false;

    int idx = 0;

    std::vector<List> lists;
    std::string link;
};


TracyLlmChat::TracyLlmChat()
    : m_width( new float[NumRoles] )
    , m_parser( new MD_PARSER() )
{
    memset( m_parser, 0, sizeof( MD_PARSER ) );
    m_parser->flags = MD_FLAG_COLLAPSEWHITESPACE | MD_FLAG_PERMISSIVEAUTOLINKS | MD_FLAG_NOHTML;
    m_parser->enter_block = []( MD_BLOCKTYPE type, void* detail, void* ud ) -> int { return ((Markdown*)ud)->EnterBlock( type, detail ); };
    m_parser->leave_block = []( MD_BLOCKTYPE type, void* detail, void* ud ) -> int { return ((Markdown*)ud)->LeaveBlock( type, detail ); };
    m_parser->enter_span = []( MD_SPANTYPE type, void* detail, void* ud ) -> int { return ((Markdown*)ud)->EnterSpan( type, detail ); };
    m_parser->leave_span = []( MD_SPANTYPE type, void* detail, void* ud ) -> int { return ((Markdown*)ud)->LeaveSpan( type, detail ); };
    m_parser->text = []( MD_TEXTTYPE type, const MD_CHAR* text, MD_SIZE size, void* ud ) -> int { return ((Markdown*)ud)->Text( type, text, size ); };
}

TracyLlmChat::~TracyLlmChat()
{
    delete m_parser;
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
    if( role != m_role )
    {
        if( m_role != TurnRole::None )
        {
            NormalScope();
            ImGui::EndGroup();
            ImGui::PopID();
        }
        m_role = role;
        m_thinkActive = false;
        m_thinkOpen = false;

        bool hover = false;
        ImGui::Spacing();
        ImGui::PushID( m_roleIdx++ );
        auto diff = m_maxWidth - m_width[(int)role];
        if( ImGui::IsMouseHoveringRect( ImGui::GetCursorScreenPos(), ImGui::GetCursorScreenPos() + ImVec2( m_maxWidth, ImGui::GetTextLineHeight() ) ) )
        {
            diff = m_maxWidth - m_width[(int)TurnRole::Trash];
            hover = true;
        }
        const auto offset = diff / 2;
        ImGui::Dummy( ImVec2( offset, 0 ) );
        ImGui::SameLine( 0, 0 );
        if( hover )
        {
            const auto& trash = roles[(int)TurnRole::Trash];
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

    ImGui::PushStyleColor( ImGuiCol_Text, roleData.textColor );
    if( role == TurnRole::Error )
    {
        ImGui::PushFont( g_fonts.mono );
        ImGui::TextWrapped( "%s", content.c_str() );
        ImGui::PopFont();
    }
    else if( role == TurnRole::Attachment )
    {
        NormalScope();
        ImGui::PushID( m_thinkIdx++ );
        if( ImGui::TreeNode( "Attachment" ) )
        {
            ImGui::PushFont( g_fonts.mono );
            ImGui::TextWrapped( "%s", content.c_str() + sizeof( "<attachment>\n" ) - 1 );
            ImGui::PopFont();
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
    else if( role != TurnRole::Assistant )
    {
        PrintMarkdown( content.c_str(), content.size() );
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

void TracyLlmChat::PrintMarkdown( const char* str, size_t size )
{
    ImGui::PushStyleVar( ImGuiStyleVar_ItemSpacing, ImVec2( ImGui::GetStyle().ItemSpacing.x, 0.0f ) );

    Markdown md;
    md_parse( str, size, m_parser, &md );

    ImGui::PopStyleVar();
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
