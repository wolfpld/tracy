#include <array>
#include <md4c.h>
#include <string>
#include <string.h>
#include <vector>

#include "TracyMarkdown.hpp"
#include "TracyMouse.hpp"
#include "TracyImGui.hpp"
#include "TracySourceContents.hpp"
#include "TracyWeb.hpp"
#include "../Fonts.hpp"

namespace tracy
{

class MarkdownContext
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
            glue = false;
            break;
        case MD_BLOCK_CODE:
        {
            char tmp[64];
            sprintf( tmp, "##code%d", idx++ );
            Separate();
            ImGui::PushStyleColor( ImGuiCol_FrameBg, ImVec4( 0, 0, 0, 0.2f ) );
            ImGui::BeginChild( tmp, ImVec2( 0, 0 ), ImGuiChildFlags_FrameStyle | ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY, ImGuiWindowFlags_HorizontalScrollbar );
            codeBlock = true;
            break;
        }
        case MD_BLOCK_TABLE:
        {
            char tmp[64];
            sprintf( tmp, "##table%d", idx++ );
            Separate();
            ImGui::BeginTable( tmp, ((MD_BLOCK_TABLE_DETAIL*)detail)->col_count, ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_Borders | ImGuiTableFlags_SizingStretchProp );
            break;
        }
        case MD_BLOCK_THEAD:
            tableHeader = true;
            break;
        case MD_BLOCK_TR:
            ImGui::TableNextRow( tableHeader ? ImGuiTableRowFlags_Headers : ImGuiTableRowFlags_None );
            break;
        case MD_BLOCK_TH:
        case MD_BLOCK_TD:
            ImGui::TableNextColumn();
            break;
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
            break;
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
            ImGui::PopStyleColor();
            separate = true;
            codeBlock = false;
            break;
        case MD_BLOCK_TABLE:
            ImGui::EndTable();
            separate = true;
            break;
        case MD_BLOCK_THEAD:
            tableHeader = false;
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
        constexpr std::array FontSizes = {
            1.f,
            2.05f,
            1.9f,
            1.75f,
            1.6f,
            1.45f,
            1.3f,
            1.15f
        };

        switch( type )
        {
        case MD_TEXT_NORMAL:
        case MD_TEXT_ENTITY:
        case MD_TEXT_HTML:
        {
            auto font = g_fonts.normal;
            if( bold > 0 )
            {
                font = italic > 0 ? g_fonts.boldItalic : g_fonts.bold;
            }
            else if( italic > 0 )
            {
                font = g_fonts.italic;
            }
            ImGui::PushFont( font, FontNormal * FontSizes[header] );

            if( !link.empty() ) ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.55f, 0.55f, 1.f, 1.f ) );
            Glue();
            const auto hovered = PrintTextWrapped( text, text + size );
            ImGui::PopFont();
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
                ImGui::PushFont( g_fonts.mono, FontNormal * FontSizes[header] );
                if( codeBlock )
                {
                    SourceContents sc;
                    sc.Parse( text, size );
                    PrintSource( sc.get() );
                }
                else
                {
                    PrintTextWrapped( text, text + size );
                }
                ImGui::PopFont();
            }
            break;
        }
        first = false;
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
    bool first = true;
    bool codeBlock = false;
    bool tableHeader = false;

    int idx = 0;

    std::vector<List> lists;
    std::string link;
};


Markdown::Markdown()
    : m_parser( new MD_PARSER() )
{
    memset( m_parser, 0, sizeof( MD_PARSER ) );
    m_parser->flags = MD_FLAG_COLLAPSEWHITESPACE | MD_FLAG_PERMISSIVEAUTOLINKS | MD_FLAG_NOHTML | MD_FLAG_TABLES;
    m_parser->enter_block = []( MD_BLOCKTYPE type, void* detail, void* ud ) -> int { return ((MarkdownContext*)ud)->EnterBlock( type, detail ); };
    m_parser->leave_block = []( MD_BLOCKTYPE type, void* detail, void* ud ) -> int { return ((MarkdownContext*)ud)->LeaveBlock( type, detail ); };
    m_parser->enter_span = []( MD_SPANTYPE type, void* detail, void* ud ) -> int { return ((MarkdownContext*)ud)->EnterSpan( type, detail ); };
    m_parser->leave_span = []( MD_SPANTYPE type, void* detail, void* ud ) -> int { return ((MarkdownContext*)ud)->LeaveSpan( type, detail ); };
    m_parser->text = []( MD_TEXTTYPE type, const MD_CHAR* text, MD_SIZE size, void* ud ) -> int { return ((MarkdownContext*)ud)->Text( type, text, size ); };
}

Markdown::~Markdown()
{
    delete m_parser;
}

void Markdown::Print( const char* str, size_t size )
{
    ImGui::PushStyleVar( ImGuiStyleVar_ItemSpacing, ImVec2( ImGui::GetStyle().ItemSpacing.x, 0.0f ) );

    MarkdownContext md;
    md_parse( str, size, m_parser, &md );

    ImGui::PopStyleVar();
}

}
