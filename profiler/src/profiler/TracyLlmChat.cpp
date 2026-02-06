#include <array>
#include <assert.h>
#include <md4c.h>
#include <nlohmann/json.hpp>
#include <string>

#include "TracyImGui.hpp"
#include "TracyLlmChat.hpp"
#include "TracyMouse.hpp"
#include "../Fonts.hpp"
#include "../../public/common/TracyForceInline.hpp"

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
    RoleData { ICON_FA_FILE, ImVec4( 0.5f, 0.75f, 1.f, 1.f ), ImVec4( 0.65f, 0.75f, 1.f, 1.f ) },
    RoleData { ICON_FA_ROBOT, ImVec4( 0.4f, 0.5f, 1.f, 1.f ), ImVec4( 1.f, 1.f, 1.f, 1.f ) },
    RoleData { ICON_FA_CIRCLE_EXCLAMATION, ImVec4( 1.f, 0.25f, 0.25f, 1.f ), ImVec4( 1.f, 0.25f, 0.25f, 1.f ) },
    RoleData { ICON_FA_TRASH, ImVec4( 1.0f, 0.25f, 0.25f, 1.f ), ImVec4( 1.f, 1.f, 1.f, 1.f ) },
    RoleData { ICON_FA_ARROWS_ROTATE, ImVec4( 1.0f, 0.25f, 0.25f, 1.f ), ImVec4( 1.f, 1.f, 1.f, 1.f ) },
};
constexpr size_t NumRoles = roles.size();

static_assert( NumRoles == (int)TracyLlmChat::TurnRole::None );


static tracy_force_inline int codepointlen( char c )
{
    if( ( c & 0x80 ) == 0 ) return 1;
    if( ( c & 0x20 ) == 0 ) return 2;
    if( ( c & 0x10 ) == 0 ) return 3;
    assert( ( c & 0x08 ) == 0 );
    return 4;
}

static size_t utflen( const char* str )
{
    size_t ret = 0;
    while( *str != '\0' )
    {
        str += codepointlen( *str );
        ret++;
    }
    return ret;
}

static const char* utfendl( const char* str, int len )
{
    int l = 0;
    while( l < len && *str != '\0' )
    {
        str += codepointlen( *str );
        l++;
    }
    return str;
}


static std::string ToolCallDescription( const nlohmann::json& json )
{
    if( !json.contains( "arguments" ) ) return "";
    nlohmann::json args;
    try
    {
        args = nlohmann::json::parse( json["arguments"].get_ref<const std::string&>() );
    }
    catch( nlohmann::json::exception& )
    {
        return "";
    }

    auto& name = json["name"].get_ref<const std::string&>();
    if( name == "search_wikipedia" )
    {
        if( !args.contains( "query" ) || !args.contains( "language" ) ) return "";
        return "Search Wikipedia (" + args["language"].get_ref<const std::string&>() + "): " + args["query"].get_ref<const std::string&>();
    }
    else if( name == "get_wikipedia" )
    {
        if( !args.contains( "page" ) || !args.contains( "language" ) ) return "";
        return "Wikipedia (" + args["language"].get_ref<const std::string&>() + "): " + args["page"].get_ref<const std::string&>();
    }
    else if( name == "get_dictionary" )
    {
        if( !args.contains( "word" ) || !args.contains( "language" ) ) return "";
        return "Dictionary (" + args["language"].get_ref<const std::string&>() + "): " + args["word"].get_ref<const std::string&>();
    }
    else if( name == "search_web" )
    {
        if( !args.contains( "query" ) ) return "";
        return "Search web: " + args["query"].get_ref<const std::string&>();
    }
    else if( name == "get_webpage" )
    {
        if( !args.contains( "url" ) ) return "";
        return "Get webpage: " + args["url"].get_ref<const std::string&>();
    }
    else if( name == "user_manual" )
    {
        if( !args.contains( "query" ) ) return "";
        return "User manual: " + args["query"].get_ref<const std::string&>();
    }
    else if( name == "source_file" )
    {
        if( !args.contains( "file" ) || !args.contains( "line" ) ) return "";
        uint32_t ctx = args.contains( "context" ) ? args["context"].get<uint32_t>() : 2;
        uint32_t ctxBack = args.contains( "context_back" ) ? args["context_back"].get<uint32_t>() : 2;
        return "Source file: " + args["file"].get_ref<const std::string&>() + ":" + std::to_string( args["line"].get<uint32_t>() ) + " (+" + std::to_string( ctx ) + ", -" + std::to_string( ctxBack ) + ")";
    }
    else if( name == "source_search" )
    {
        if( !args.contains( "query" ) ) return "";
        std::string caseInsensitive, path;
        if( args.contains( "case_insensitive" ) && args["case_insensitive"].get<bool>() ) caseInsensitive = " (case insensitive)";
        if( args.contains( "path" ) ) path = ", path: " + args["path"].get_ref<const std::string&>();
        return "Source search: " + args["query"].get_ref<const std::string&>() + caseInsensitive + path;
    }
    return "";
}


TracyLlmChat::TracyLlmChat( View& view, Worker& worker )
    : m_width( new float[NumRoles] )
    , m_markdown( &view, &worker )
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

bool TracyLlmChat::Turn( TurnRole role, std::vector<nlohmann::json>::iterator it, const std::vector<nlohmann::json>::iterator& end, Think think, bool last )
{
    auto& json = *it;
    if( json.contains( "role" ) && json["role"].get_ref<const std::string&>() == "tool" ) return true;

    bool keep = true;
    const auto& roleData = roles[(int)role];
    const bool roleChange = role != m_role;
    if( roleChange || role == TurnRole::Attachment || role == TurnRole::Error )
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
        if( roleChange )
        {
            m_role = role;
            ImGui::Spacing();
        }
        int trashIdx = role == TurnRole::Assistant ? (int)TurnRole::Regenerate : (int)TurnRole::Trash;
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
            if( IsMouseClicked( ImGuiMouseButton_Left ) && ImGui::IsWindowHovered() ) keep = false;
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
        if( json.contains( "content" ) )
        {
            ImGui::TextWrapped( "%s", json["content"].get_ref<const std::string&>().c_str() );
        }
        else
        {
            ImGui::TextWrapped( "No content in error message. This shouldn't happen?" );
        }
        ImGui::PopFont();
    }
    else if( role == TurnRole::Attachment )
    {
        constexpr auto tagSize = sizeof( "<attachment>\n" ) - 1;

        if( json.contains( "content" ) )
        {
            auto& content = json["content"].get_ref<const std::string&>();
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
                ImGui::TextWrapped( "%s", j.dump( 2 ).c_str() );
                ImGui::PopFont();
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
        else
        {
            ImGui::TextWrapped( "No content in attachment. This shouldn't happen?" );
        }
    }
    else if( role != TurnRole::Assistant )
    {
        if( json.contains( "content" ) )
        {
            auto& content = json["content"].get_ref<const std::string&>();
            m_markdown.Print( content.c_str(), content.size() );
        }
    }
    else
    {
        if( think == Think::Show && json.contains( "reasoning_content" ) )
        {
            auto& reasoning = json["reasoning_content"].get_ref<const std::string&>();
            ThinkScope( !roleChange );
            if( m_thinkOpen )
            {
                PrintThink( reasoning.c_str(), reasoning.size() );
            }
            else if( last && !json.contains( "content" ) )
            {
                const auto cutlen = std::max( int( utflen( reasoning.c_str() ) ) - 40, 0 );
                const auto cut = utfendl( reasoning.c_str(), cutlen );
                std::string str = cut;
                for( auto& c : str )
                {
                    if( c == '\n' ) c = ' ';
                }
                ImGui::SameLine();
                ImGui::PushStyleColor( ImGuiCol_Text, 0xFF555555 );
                ImGui::Text( "…%s", str.c_str() );
                ImGui::PopStyleColor();
            }
        }
        if( json.contains( "content" ) )
        {
            auto& roleStr = json["role"].get_ref<const std::string&>();
            assert( roleStr != "tool" );
            auto& content = json["content"].get_ref<const std::string&>();
            if( !content.empty() )
            {
                auto ptr = content.c_str();
                auto end = ptr + content.size();
                while( *ptr == '\n' ) ptr++;
                if( ptr != end )
                {
                    NormalScope();
                    m_markdown.Print( content.c_str(), content.size() );
                    if( !last && think == Think::Hide && roleStr == "assistant" ) ImGui::Spacing();
                }
            }
        }
        if( think != Think::Hide && json.contains( "tool_calls" ) )
        {
            ThinkScope( !roleChange || json.contains( "content" ) );
            if( m_thinkOpen )
            {
                ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.5f, 0.5f, 0.5f, 1.f ) );
                if( json.contains( "reasoning_content" ) ) ImGui::Spacing();
                bool first = true;
                for( auto& call : json["tool_calls"] )
                {
                    if( call.contains( "id" ) && call.contains( "function" ) )
                    {
                        auto& id = call["id"].get_ref<const std::string&>();
                        auto& function = call["function"];
                        if( function.contains( "name" ) )
                        {
                            if( first ) first = false;
                            else ImGui::Spacing();

                            std::string tmp = "##" + id;
                            auto open = ImGui::TreeNodeEx( tmp.c_str(), ImGuiTreeNodeFlags_SpanAvailWidth );
                            ImGui::SameLine();
                            const auto desc = ToolCallDescription( function );
                            if( desc.empty() )
                            {
                                auto& name = function["name"].get_ref<const std::string&>();
                                ImGui::Text( "Tool call (%s/%s)…", name.c_str(), id.substr( 0, 8 ).c_str() );
                            }
                            else
                            {
                                ImGui::TextUnformatted( desc.c_str() );
                            }
                            if( open )
                            {
                                if( desc.empty() && function.contains( "arguments" ) )
                                {
                                    try
                                    {
                                        auto args = nlohmann::json::parse( function["arguments"].get_ref<const std::string&>() );
                                        if( !args.empty() )
                                        {
                                            ImGui::Indent();
                                            for( auto& [key, value] : args.items() )
                                            {
                                                ImGui::Text( "%s: %s", key.c_str(), value.dump().c_str() );
                                            }
                                            ImGui::Unindent();
                                        }
                                    }
                                    catch( nlohmann::json::exception& )
                                    {
                                        ImGui::Indent();
                                        ImGui::TextWrapped( "%s", function["arguments"].get_ref<const std::string&>().c_str() );
                                        ImGui::Unindent();
                                    }
                                }

                                for( auto result = it+1; result != end; result++ )
                                {
                                    auto& rjson = *result;
                                    if( !rjson.contains( "role" ) || rjson["role"].get_ref<const std::string&>() != "tool" ) continue;
                                    if( id != rjson["tool_call_id"].get_ref<const std::string&>() ) continue;
                                    if( !rjson.contains( "content" ) ) continue;
                                    auto& content = rjson["content"].get_ref<const std::string&>();
                                    if( content.empty() ) continue;

                                    if( content == ForgetMsg )
                                    {
                                        ImGui::TextUnformatted( ICON_FA_RECYCLE " Tool response removed to save context space" );
                                    }
                                    else
                                    {
                                        std::string parsed;
                                        try
                                        {
                                            parsed = nlohmann::json::parse( content.c_str() ).dump( 2 );
                                        }
                                        catch( nlohmann::json::exception& )
                                        {
                                            parsed = content;
                                        }
                                        ImGui::PushFont( g_fonts.mono, FontNormal );
                                        ImGui::TextWrapped( "%s", parsed.c_str() );
                                        ImGui::PopFont();
                                    }
                                    break;
                                }

                                ImGui::TreePop();
                            }
                        }
                    }
                }
                ImGui::PopStyleColor();
            }
        }
    }
    ImGui::PopStyleColor();

    if( json.contains( "content" ) )
    {
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
                ImGui::SetClipboardText( json["content"].get_ref<const std::string&>().c_str() );
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
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

void TracyLlmChat::ThinkScope( bool spacing )
{
    if( m_thinkActive ) return;
    m_thinkActive = true;
    if( spacing ) ImGui::Spacing();
    ImGui::PushID( m_thinkIdx++ );
    ImGui::PushStyleColor( ImGuiCol_Text, ThinkColor );
    m_thinkOpen = ImGui::TreeNode( ICON_FA_LIGHTBULB " Internal thoughts…" );
}

void TracyLlmChat::PrintThink( const char* str, size_t size )
{
    ImGui::PushStyleColor( ImGuiCol_Text, ThinkColor );
    m_markdown.Print( str, size );
    ImGui::PopStyleColor();
}

}
