#ifndef __TRACYLLMMARKDOWN_HPP__
#define __TRACYLLMMARKDOWN_HPP__

#include <md4c.h>
#include <string>
#include <vector>

#include "TracyMouse.hpp"
#include "TracyImGui.hpp"
#include "TracySourceContents.hpp"
#include "TracyWeb.hpp"
#include "../Fonts.hpp"

namespace tracy
{

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
            glue = false;
            break;
        case MD_BLOCK_CODE:
        {
            char tmp[64];
            sprintf( tmp, "##code%d", idx++ );
            Separate();
            ImGui::PushStyleColor( ImGuiCol_FrameBg, ImVec4( 0, 0, 0, 0.2f ) );
            ImGui::BeginChild( tmp, ImVec2( 0, 0 ), ImGuiChildFlags_FrameStyle | ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY );
            codeBlock = true;
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
                if( !first && !glue ) ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.5f ) );
                ImGui::PushFont( g_fonts.normal, FontBig );
            }
            else if( bold > 0 )
            {
                ImGui::PushFont( italic > 0 ? g_fonts.boldItalic : g_fonts.bold, FontNormal );
            }
            else if( italic > 0 )
            {
                ImGui::PushFont( g_fonts.italic, FontNormal );
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
                ImGui::PushFont( g_fonts.mono, FontNormal );
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

    int idx = 0;

    std::vector<List> lists;
    std::string link;
};

}

#endif
