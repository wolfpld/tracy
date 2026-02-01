#include <array>
#include <md4c.h>
#include <string>
#include <string.h>
#include <vector>

#include "TracyFilesystem.hpp"
#include "TracyMarkdown.hpp"
#include "TracyMouse.hpp"
#include "TracyImGui.hpp"
#include "TracySourceContents.hpp"
#include "TracyView.hpp"
#include "TracyWeb.hpp"
#include "../Fonts.hpp"


#ifdef _MSC_VER
void* memmem( const void* haystack, size_t hsize, const char* needle, size_t nsize )
{
    auto left = ptrdiff_t( hsize ) - ptrdiff_t( nsize );
    while( left >= 0 )
    {
        if( memcmp( haystack, needle, nsize ) == 0 ) return (char*)haystack;
        haystack = (char*)haystack + 1;
        left--;
    }
    return nullptr;
}
#endif


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
    MarkdownContext( View* view, Worker* worker ) : m_view( view ), m_worker( worker ) {}

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
            auto li = ((MD_BLOCK_LI_DETAIL*)detail);
            if( li->is_task )
            {
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( -2, -2 ) );
                char tmp[64];
                sprintf( tmp, "##task%d", idx++ );
                bool checked = li->task_mark != ' ';
                ImGui::BeginDisabled();
                ImGui::Checkbox( tmp, &checked );
                ImGui::EndDisabled();
                ImGui::PopStyleVar();
            }
            else
            {
                auto& l = lists.back();
                if( l.num < 0 )
                {
                    ImGui::Bullet();
                }
                else
                {
                    ImGui::Text( "%d.", l.num++ );
                }
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
            ImGui::BeginTable( tmp, ((MD_BLOCK_TABLE_DETAIL*)detail)->col_count, ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_Borders | ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_Resizable );
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
        case MD_BLOCK_TH:
        case MD_BLOCK_TD:
            glue = false;
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
        case MD_SPAN_DEL:
            strikethrough = true;
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
        case MD_SPAN_DEL:
            strikethrough = false;
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
            1.7f,
            1.6f,
            1.5f,
            1.4f,
            1.3f,
            1.2f,
            1.1f
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
            Glue();
            PrintTextExt( text, text + size );
            break;
        }
        case MD_TEXT_NULLCHAR:
            Glue();
            PrintTextExt( "\xEF\xBF\xBD", nullptr, false );
            break;
        case MD_TEXT_BR:
            glue = false;
            break;
        case MD_TEXT_SOFTBR:
            Glue();
            PrintTextExt( " ", nullptr, false );
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
                if( codeBlock )
                {
                    SourceContents sc;
                    sc.Parse( text, size );
                    ImGui::PushFont( g_fonts.mono, FontNormal * FontSizes[header] );
                    PrintSource( sc.get() );
                    ImGui::PopFont();
                }
                else
                {
                    ImGui::PushFont( g_fonts.mono, FontNormal * FontSizes[header] );
                    PrintTextExt( text, text + size );
                }
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

    bool PrintText( const char* text, const char* end = nullptr )
    {
        if( !end ) end = text + strlen( text );

        auto pos = (const char*)memmem( text, end - text, "\xe2\x80\xaf", 3 );
        if( !pos ) return PrintTextWrapped( text, end, strikethrough, !link.empty() );

        // Replace narrow no-break space with no-break space
        std::string buf( text, end );
        auto found = std::string::size_type( pos - text );
        while( found != std::string::npos )
        {
            buf.replace( found, 3, "\xc2\xa0" );
            found = buf.find( "\xe2\x80\xaf", found );
        }
        text = buf.c_str();
        end = text + buf.size();

        return PrintTextWrapped( text, end, strikethrough, !link.empty() );
    }

    void PrintTextExt( const char* text, const char* end = nullptr, bool popFont = true )
    {
        if( !link.empty() ) ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.55f, 0.55f, 1.f, 1.f ) );
        const auto hovered = PrintText( text, end );
        if( popFont ) ImGui::PopFont();
        if( !link.empty() )
        {
            ImGui::PopStyleColor();
            if( hovered ) LinkHover();
        }
    }

    void LinkHover()
    {
        const auto isSource = link.starts_with( "source:" );
        StringIdx idx;
        uint32_t line = 0;

        ImGui::SetMouseCursor( ImGuiMouseCursor_Hand );
        ImGui::BeginTooltip();
        ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 1.f, 1.f, 1.f ) );
        if( isSource && m_view && m_worker )
        {
            std::string source = link.substr( 7 );
            auto separator = source.find_last_of( ':' );
            auto fn = source.substr( 0, separator );
            auto fnidx = m_worker->FindStringIdx( fn.c_str() );
            if( fnidx != 0 && SourceFileValid( fn.c_str(), m_worker->GetCaptureTime(), *m_view, *m_worker ) )
            {
                idx.SetIdx( fnidx );
            }

            TextFocused( "Source:", fn.c_str() );
            if( separator != std::string::npos )
            {
                line = atoi( source.substr( separator + 1 ).c_str() );
                ImGui::SameLine( 0, 0 );
                ImGui::Text( ":%i", line );
            }

            if( idx.Active() )
            {
                ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.25f ) );
                ImGui::Separator();
                ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.25f ) );
                m_view->DrawSourceTooltip( fn.c_str(), line, 3, 3, false );
            }
            else
            {
                TextColoredUnformatted( ImVec4( 1.f, 0.f, 0.f, 1.f ), "Invalid source file reference" );
            }
        }
        else
        {
            ImGui::TextUnformatted( link.c_str() );
        }
        ImGui::PopStyleColor();
        ImGui::EndTooltip();
        if( IsMouseClicked( ImGuiMouseButton_Left ) )
        {
            if( isSource && m_view && m_worker )
            {
                if( idx.Active() )
                {
                    auto str = m_worker->GetString( idx );
                    m_view->ViewSource( str, line );
                }
            }
            else
            {
                OpenWebpage( link.c_str() );
            }
        }
    }

    int bold = 0;
    int italic = 0;
    int header = 0;

    bool glue = false;
    bool separate = false;
    bool first = true;
    bool codeBlock = false;
    bool tableHeader = false;
    bool strikethrough = false;

    int idx = 0;

    std::vector<List> lists;
    std::string link;

    View* m_view;
    Worker* m_worker;
};


Markdown::Markdown( View* view, Worker* worker )
    : m_parser( new MD_PARSER() )
    , m_view( view )
    , m_worker( worker )
{
    memset( m_parser, 0, sizeof( MD_PARSER ) );
    m_parser->flags = MD_FLAG_COLLAPSEWHITESPACE | MD_FLAG_PERMISSIVEAUTOLINKS | MD_FLAG_NOHTML | MD_FLAG_TABLES | MD_FLAG_TASKLISTS | MD_FLAG_STRIKETHROUGH;
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

    MarkdownContext md( m_view, m_worker );
    md_parse( str, size, m_parser, &md );

    ImGui::PopStyleVar();
}

}
