#include <curl/curl.h>
#include <ollama.hpp>
#include <stdint.h>
#include <stdlib.h>
#include <ranges>
#include <time.h>

#include "TracyConfig.hpp"
#include "TracyImGui.hpp"
#include "TracyLlm.hpp"
#include "TracyPrint.hpp"

#include "data/SystemPrompt.hpp"

extern tracy::Config s_config;

namespace tracy
{

extern double s_time;

constexpr size_t InputBufferSize = 1024;

TracyLlm::TracyLlm()
    : m_exit( false )
    , m_input( nullptr )
{
    if( !s_config.llm ) return;

    try
    {
        m_ollama = std::make_unique<Ollama>( s_config.llmAddress );
        if( !m_ollama->is_running() )
        {
            m_ollama.reset();
            return;
        }
    }
    catch( const std::exception& e )
    {
        m_ollama.reset();
        return;
    }

    m_input = new char[InputBufferSize];
    *m_input = 0;

    m_systemPrompt = Unembed( SystemPrompt );

    ResetChat();

    m_jobs.emplace_back( WorkItem {
        .task = Task::LoadModels,
        .callback = [this] { UpdateModels(); }
    } );
    m_thread = std::thread( [this] { Worker(); } );
}

TracyLlm::~TracyLlm()
{
    delete[] m_input;

    if( m_thread.joinable() )
    {
        {
            std::lock_guard lock( m_lock );
            m_stop = true;
            m_exit.store( true, std::memory_order_release );
            m_cv.notify_all();
        }
        m_thread.join();
    }
}

std::string TracyLlm::GetVersion() const
{
    return m_ollama->get_version();
}

void TracyLlm::Draw()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 400 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Tracy AI", &m_show, ImGuiWindowFlags_NoScrollbar );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    if( !m_ollama )
    {
        const auto ty = ImGui::GetTextLineHeight();
        ImGui::PushFont( m_bigFont );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 - ty ) * 0.5f ) );
        TextCentered( ICON_FA_PLUG_CIRCLE_XMARK );
        TextCentered( "Cannot connect to ollama server!" );
        ImGui::PopFont();
        ImGui::Dummy( ImVec2( 0, ty * 2 ) );
        ImGui::PushFont( m_smallFont );
        TextCentered( "Server address:" );
        TextCentered( s_config.llmAddress.c_str() );
        ImGui::PopFont();
        ImGui::End();
        return;
    }
    if( IsBusy() )
    {
        ImGui::PushFont( m_bigFont );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
        TextCentered( ICON_FA_HOURGLASS );
        TextCentered( "Please wait..." );
        DrawWaitingDots( s_time );
        ImGui::PopFont();
        ImGui::End();
        return;
    }

    auto& style = ImGui::GetStyle();
    std::lock_guard lock( m_lock );

    if( ImGui::Button( ICON_FA_BROOM " Clear chat" ) )
    {
        if( m_responding ) m_stop = true;
        ResetChat();
        m_chatCache.clear();
        *m_input = 0;
    }
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_ARROWS_ROTATE " Reload models" ) )
    {
        if( m_responding ) m_stop = true;
        m_jobs.emplace_back( WorkItem {
            .task = Task::LoadModels,
            .callback = [this] { UpdateModels(); }
        } );
        m_cv.notify_all();
    }

    ImGui::SameLine();
    if( ImGui::TreeNode( "Settings" ) )
    {
        ImGui::Spacing();
        ImGui::AlignTextToFramePadding();
        TextDisabledUnformatted( "Model:" );
        ImGui::SameLine();
        if( ImGui::BeginCombo( "##model", m_models[m_modelIdx].name.c_str() ) )
        {
            for( size_t i = 0; i < m_models.size(); ++i )
            {
                const auto& model = m_models[i];
                if( ImGui::Selectable( model.name.c_str(), i == m_modelIdx ) )
                {
                    m_modelIdx = i;
                    s_config.llmModel = model.name;
                }
                if( m_modelIdx == i ) ImGui::SetItemDefaultFocus();
                ImGui::SameLine();
                ImGui::TextDisabled( "(max context: %s)", tracy::RealToString( m_models[i].ctxSize ) );
            }
            ImGui::EndCombo();
        }

        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted( "Context size:" );
        ImGui::SameLine();
        ImGui::SetNextItemWidth( 120 * scale );
        if( ImGui::InputInt( "##contextsize", &s_config.llmContext, 1024, 8192 ) )
        {
            s_config.llmContext = std::clamp( s_config.llmContext, 2048, 10240 * 1024 );
        }
        ImGui::Indent();
        if( ImGui::Button( "4K" ) ) s_config.llmContext = 4 * 1024;
        ImGui::SameLine();
        if( ImGui::Button( "8K" ) ) s_config.llmContext = 8 * 1024;
        ImGui::SameLine();
        if( ImGui::Button( "16K" ) ) s_config.llmContext = 16 * 1024;
        ImGui::SameLine();
        if( ImGui::Button( "32K" ) ) s_config.llmContext = 32 * 1024;
        ImGui::SameLine();
        if( ImGui::Button( "64K" ) ) s_config.llmContext = 64 * 1024;
        ImGui::SameLine();
        if( ImGui::Button( "128K" ) ) s_config.llmContext = 128 * 1024;
        ImGui::Unindent();

        ImGui::TreePop();
    }

    const auto ctxSize = std::min( m_models[m_modelIdx].ctxSize, s_config.llmContext );
    ImGui::Spacing();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    ImGui::ProgressBar( m_usedCtx / (float)ctxSize, ImVec2( -1, 0 ), "" );
    ImGui::PopStyleVar();
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        TextFocused( "Used context size:", RealToString( m_usedCtx ) );
        ImGui::SameLine();
        char buf[64];
        PrintStringPercent( buf, m_usedCtx / (float)ctxSize * 100 );
        tracy::TextDisabledUnformatted( buf );
        TextFocused( "Available context size:", RealToString( ctxSize ) );
        ImGui::EndTooltip();
    }

    ImGui::Spacing();
    ImGui::BeginChild( "##ollama", ImVec2( 0, -( ImGui::GetFrameHeight() + style.ItemSpacing.y * 2 ) ), ImGuiChildFlags_Borders, ImGuiWindowFlags_AlwaysVerticalScrollbar );
    if( m_chat->size() <= 1 )   // account for system prompt
    {
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 10 ) * 0.5f ) );
        ImGui::PushStyleColor( ImGuiCol_Text, style.Colors[ImGuiCol_TextDisabled] );
        ImGui::TextWrapped( "What I had not realized is that extremely short exposures to a relatively simple computer program could induce powerful delusional thinking in quite normal people." );
        ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.5f ) );
        const auto tw = ImGui::CalcTextSize( "-- Joseph Weizenbaum, 1976" ).x;
        ImGui::SetCursorPosX( ( ImGui::GetWindowWidth() - tw - 30 * scale ) );
        ImGui::TextUnformatted( "-- Joseph Weizenbaum, 1976" );
        ImGui::PopStyleColor();
    }
    else
    {
        ImGui::PushID( m_chatId );
        int idx = 0;
        int num = 0;
        bool first = true;
        bool wasToolResponse = false;
        for( auto& line : *m_chat )
        {
            const auto uw = ImGui::CalcTextSize( ICON_FA_USER ).x;
            const auto rw = ImGui::CalcTextSize( ICON_FA_ROBOT ).x;
            const auto ew = ImGui::CalcTextSize( ICON_FA_CIRCLE_EXCLAMATION ).x;
            const auto yw = ImGui::CalcTextSize( ICON_FA_REPLY ).x;
            const auto mw = std::max( { uw, rw, ew, yw } );

            const auto posStart = ImGui::GetCursorPos().x;
            const auto& role = line["role"].get_ref<const std::string&>();

            if( role == "system" ) continue;

            const auto isUser = role == "user";
            const auto isError = role == "error";
            const auto isAssistant = role == "assistant";
            const auto isToolResponse = role == "tool";

            if( first )
            {
                first = false;
            }
            else if( !isToolResponse && !wasToolResponse )
            {
                ImGui::Spacing();
            }

            wasToolResponse = isToolResponse;

            float diff, offset;
            if( isUser )
            {
                diff = mw - uw;
                offset = diff / 2;
                ImGui::Dummy( ImVec2( offset, 0 ) );
                ImGui::SameLine( 0, 0 );
                ImGui::TextColored( ImVec4( 0.75f, 1.f, 0.25f, 1.f ), ICON_FA_USER );
            }
            else if( isError )
            {
                diff = mw - ew;
                offset = diff / 2;
                ImGui::Dummy( ImVec2( offset, 0 ) );
                ImGui::SameLine( 0, 0 );
                ImGui::TextColored( ImVec4( 1.f, 0.25f, 0.25f, 1.f ), ICON_FA_CIRCLE_EXCLAMATION );
            }
            else if( isAssistant )
            {
                diff = mw - rw;
                offset = diff / 2;
                ImGui::Dummy( ImVec2( offset, 0 ) );
                ImGui::SameLine( 0, 0 );
                ImGui::TextColored( ImVec4( 0.4f, 0.5f, 1.f, 1.f ), ICON_FA_ROBOT );
            }
            else if( isToolResponse )
            {
                diff = mw - yw;
                offset = diff / 2;
                ImGui::Dummy( ImVec2( offset, 0 ) );
                ImGui::SameLine( 0, 0 );
                ImGui::TextColored( style.Colors[ImGuiCol_TextDisabled], ICON_FA_REPLY );
            }
            else
            {
                assert( false );
            }

            ImGui::SameLine( 0, 0 );
            ImGui::Dummy( ImVec2( diff - offset, 0 ) );
            ImGui::SameLine();
            ImGui::BeginGroup();

            if( isUser )
            {
                ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.65f, 0.65f, 0.65f, 1.f ) );
            }
            else if( isError )
            {
                ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 0.25f, 0.25f, 1.f ) );
            }
            else if( isToolResponse )
            {
                ImGui::PushStyleColor( ImGuiCol_Text, style.Colors[ImGuiCol_TextDisabled] );
            }
            else if( isAssistant )
            {
                ImGui::PushStyleColor( ImGuiCol_Text, style.Colors[ImGuiCol_Text] );
            }
            else
            {
                assert( false );
            }

            if( isToolResponse )
            {
                ImGui::PushID( idx );
                if( ImGui::TreeNode( "Tool response..." ) )
                {
                    ImGui::PushFont( m_font );
                    ImGui::TextWrapped( "%s", line["content"].get_ref<const std::string&>().c_str() );
                    ImGui::PopFont();
                    ImGui::TreePop();
                }
                ImGui::PopID();
            }
            else if( isAssistant )
            {
                const auto& content = line["content"].get_ref<const std::string&>();

                auto cit = m_chatCache.find( idx );
                if( cit == m_chatCache.end() ) cit = m_chatCache.emplace( idx, ChatCache {} ).first;
                auto& cache = cit->second;

                if( cache.parsedLen != content.size() )
                {
                    UpdateCache( cache, content );
                    assert( cache.parsedLen == content.size() );
                }

                if( cache.lines.empty() && m_responding )
                {
                    tracy::TextDisabledUnformatted( "\xe2\x80\xa6" );
                }
                else
                {
                    LineContext ctx = {};
                    auto it = cache.lines.begin();
                    while( it != cache.lines.end() )
                    {
                        auto& line = *it++;
                        if( line == "<think>" )
                        {
                            ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.5f, 0.5f, 0.3f, 1.f ) );
                            ImGui::PushID( idx );
                            if( ImGui::TreeNode( ICON_FA_LIGHTBULB " Internal thoughts..." ) )
                            {
                                LineContext thinkCtx = {};
                                while( it != cache.lines.end() && *it != "</think>" )
                                {
                                    PrintLine( thinkCtx, *it++, num++ );
                                }
                                CleanContext( thinkCtx );
                                if( it != cache.lines.end() ) ++it;
                                ImGui::TreePop();
                            }
                            else
                            {
                                while( it != cache.lines.end() && *it != "</think>" ) ++it;
                                if( it != cache.lines.end() ) ++it;
                            }
                            ImGui::PopID();
                            ImGui::PopStyleColor();
                        }
                        else if( line == "<tool>" )
                        {
                            ImGui::PushStyleColor( ImGuiCol_Text, style.Colors[ImGuiCol_TextDisabled] );
                            ImGui::PushID( idx );
                            if( ImGui::TreeNode( "Tool query..." ) )
                            {
                                ImGui::PushFont( m_font );
                                while( it != cache.lines.end() && *it != "</tool>" )
                                {
                                    ImGui::TextWrapped( "%s", (*it).c_str() );
                                    ++it;
                                }
                                if( it != cache.lines.end() ) ++it;
                                ImGui::PopFont();
                                ImGui::TreePop();
                            }
                            else
                            {
                                while( it != cache.lines.end() && *it != "</tool>" ) ++it;
                                if( it != cache.lines.end() ) ++it;
                            }
                            ImGui::PopID();
                            ImGui::PopStyleColor();
                        }
                        else
                        {
                            PrintLine( ctx, line, num++ );
                        }
                    }
                    CleanContext( ctx );
                }
            }
            else
            {
                ImGui::TextWrapped( "%s", line["content"].get_ref<const std::string&>().c_str() );
            }
            ImGui::PopStyleColor();
            ImGui::EndGroup();
            idx++;
        }

        if( m_wasUpdated )
        {
            ImGui::SetScrollHereY( 1.f );
            m_wasUpdated = false;
        }
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::Spacing();

    if( m_responding )
    {
        if( ImGui::Button( ICON_FA_STOP " Stop" ) ) m_stop = true;
        ImGui::SameLine();
        const auto pos = ImGui::GetWindowPos() + ImGui::GetCursorPos();
        auto draw = ImGui::GetWindowDrawList();
        const auto ty = ImGui::GetTextLineHeight();
        draw->AddCircleFilled( pos + ImVec2( ty * 0.5f + 0 * ty, ty * 0.675f ), ty * ( 0.15f + 0.2f * ( pow( cos( s_time * 3.5f + 0.3f ), 16.f ) ) ), 0xFFBBBBBB, 12 );
        draw->AddCircleFilled( pos + ImVec2( ty * 0.5f + 1 * ty, ty * 0.675f ), ty * ( 0.15f + 0.2f * ( pow( cos( s_time * 3.5f        ), 16.f ) ) ), 0xFFBBBBBB, 12 );
        draw->AddCircleFilled( pos + ImVec2( ty * 0.5f + 2 * ty, ty * 0.675f ), ty * ( 0.15f + 0.2f * ( pow( cos( s_time * 3.5f - 0.3f ), 16.f ) ) ), 0xFFBBBBBB, 12 );
        ImGui::Dummy( ImVec2( ty * 3, ty ) );
        ImGui::SameLine();
        ImGui::TextUnformatted( "Generating..." );
        s_wasActive = true;
    }
    else
    {
        if( ImGui::IsWindowAppearing() || m_focusInput )
        {
            ImGui::SetKeyboardFocusHere( 0 );
            m_focusInput = false;
        }
        ImGui::PushItemWidth( -1 );
        if( ImGui::InputTextWithHint( "##ollama_input", "Write your question here...", m_input, InputBufferSize, ImGuiInputTextFlags_EnterReturnsTrue ) )
        {
            auto ptr = m_input;
            while( *ptr )
            {
                if( *ptr != ' ' && *ptr != '\t' && *ptr != '\n' ) break;
                ptr++;
            }
            if( *ptr )
            {
                m_chat->emplace_back( ollama::message( "user", m_input ) );
                *m_input = 0;
                m_responding = true;
                m_wasUpdated = true;

                m_jobs.emplace_back( WorkItem {
                    .task = Task::SendMessage,
                    .callback = nullptr,
                    .chat = std::make_unique<ollama::messages>( *m_chat )
                } );
                m_cv.notify_all();
            }
            else
            {
                *m_input = 0;
            }
            ImGui::SetKeyboardFocusHere( -1 );
        }
    }

    ImGui::End();
}

void TracyLlm::Worker()
{
    std::unique_lock lock( m_lock );
    while( !m_exit.load( std::memory_order_acquire ) )
    {
        m_cv.wait( lock, [this] { return !m_jobs.empty() || m_exit.load( std::memory_order_acquire ); } );
        if( m_exit.load( std::memory_order_acquire ) ) break;

        auto job = std::move( m_jobs.back() );
        m_jobs.pop_back();

        switch( job.task )
        {
        case Task::LoadModels:
            m_busy = true;
            lock.unlock();
            LoadModels();
            job.callback();
            lock.lock();
            m_busy = false;
            break;
        case Task::SendMessage:
            SendMessage( *job.chat );
            break;
        default:
            assert( false );
            break;
        }
    }
};

void TracyLlm::LoadModels()
{
    std::vector<LlmModel> m;

    const auto models = m_ollama->list_models();
    for( const auto& model : models )
    {
        const auto info = m_ollama->show_model_info( model );
        const auto& modelInfo = info["model_info"];
        const auto& architecture = modelInfo["general.architecture"].get_ref<const std::string&>();
        const auto& ctx = modelInfo[architecture + ".context_length"];
        m.emplace_back( LlmModel { .name = model, .ctxSize = ctx.get<int>() } );
    }

    m_modelsLock.lock();
    std::swap( m_models, m );
    m_modelsLock.unlock();
}

void TracyLlm::UpdateModels()
{
    auto it = std::ranges::find_if( m_models, []( const auto& model ) { return model.name == s_config.llmModel; } );
    if( it == m_models.end() )
    {
        m_modelIdx = 0;
    }
    else
    {
        m_modelIdx = std::distance( m_models.begin(), it );
    }
}

void TracyLlm::ResetChat()
{
    m_chat = std::make_unique<ollama::messages>();
    m_chat->emplace_back( ollama::message( "system", std::string( m_systemPrompt->data(), m_systemPrompt->size() ) ) );
    m_chatId++;
    m_usedCtx = 0;
}

void TracyLlm::SendMessage( const ollama::messages& messages )
{
    // The chat() call will fire a callback right away, so the assistant message needs to be there already
    m_chat->emplace_back( ollama::message( "assistant", "" ) );

    m_lock.unlock();
    bool res;
    try
    {
        ollama::request req( ollama::message_type::chat );
        req["model"] = m_models[m_modelIdx].name;
        req["messages"] = messages.to_json();
        req["stream"] = true;
        req["options"]["num_ctx"] = std::min( m_models[m_modelIdx].ctxSize, s_config.llmContext );
        req["keep_alive"] = "5m";

        res = m_ollama->chat( req, [this]( const ollama::response& response ) -> bool { return OnResponse( response ); });
    }
    catch( std::exception& e )
    {
        m_lock.lock();
        if( !m_chat->empty() && m_chat->back()["role"].get_ref<const std::string&>() == "assistant" ) m_chat->pop_back();
        m_chat->emplace_back( ollama::message( "error", e.what() ) );
        m_responding = false;
        m_stop = false;
        m_wasUpdated = true;
        return;
    }

    m_lock.lock();
    if( !res )
    {
        m_chat->pop_back();
        m_responding = false;
        m_stop = false;
    }
}

static std::vector<std::string> SplitLines( const std::string& str )
{
    std::vector<std::string> lines;
    auto pos = 0;
    while( pos < str.size() )
    {
        auto next = str.find( '\n', pos );
        if( next == std::string::npos ) next = str.size();
        if( pos != next ) lines.emplace_back( str.substr( pos, next - pos ) );
        pos = next + 1;
    }
    return lines;
}

bool TracyLlm::OnResponse( const ollama::response& response )
{
    std::lock_guard lock( m_lock );

    if( m_stop )
    {
        m_stop = false;
        m_responding = false;
        m_focusInput = true;
        return false;
    }

    auto& back = m_chat->back();
    auto& content = back["content"];
    const auto& str = content.get_ref<const std::string&>();
    auto responseStr = response.as_simple_string();
    std::erase( responseStr, '\r' );
    content = str + responseStr;
    m_wasUpdated = true;
    m_usedCtx++;

    auto& json = response.as_json();
    auto& message = json["message"];
    if( json["done"] )
    {
        bool isTool = false;
        auto& str = back["content"].get_ref<const std::string&>();
        auto pos = str.find( "<tool>\n" );
        if( pos != std::string::npos )
        {
            auto end = str.find( "\n</tool>", pos );
            if( end != std::string::npos )
            {
                auto data = str.substr( pos + 7, end - pos - 7 );
                auto lines = SplitLines( data );
                if( !lines.empty() )
                {
                    isTool = true;
                    auto tool = lines[0];
                    lines.erase( lines.begin() );
                    const auto reply = HandleToolCalls( tool, lines );
                    m_chat->emplace_back( ollama::message( "tool", reply ) );

                    m_jobs.emplace_back( WorkItem {
                        .task = Task::SendMessage,
                        .callback = nullptr,
                        .chat = std::make_unique<ollama::messages>( *m_chat )
                    } );
                    m_cv.notify_all();
                }
            }
        }
        if( !isTool )
        {
            m_responding = false;
            m_focusInput = true;
        }

        m_usedCtx = json["prompt_eval_count"].get<int>() + json["eval_count"].get<int>();
        return false;
    }

    return true;
}

void TracyLlm::UpdateCache( ChatCache& cache, const std::string& str )
{
    const auto sz = str.size();
    auto pos = cache.parsedLen;
    while( pos < sz )
    {
        const auto isNewLine = pos == 0 || str[pos - 1] == '\n';
        auto next = str.find( '\n', pos );
        if( next == std::string::npos ) next = sz;
        if( isNewLine )
        {
            cache.lines.emplace_back( str.substr( pos, next - pos ) );
        }
        else
        {
            auto& line = cache.lines.back().append( str, pos, next - pos );
        }
        pos = next + 1;
    }
    cache.parsedLen = sz;
}

static bool IsHeading( const char* str )
{
    if( *str != '#' ) return false;
    while( *str == '#' ) str++;
    return *str == ' ' || *str == '\t';
}

void TracyLlm::PrintLine( LineContext& ctx, const std::string& str, int num )
{
    if( str.empty() ) return;

    auto ptr = str.c_str();
    while( *ptr == ' ' || *ptr == '\t' ) ptr++;
    if( strncmp( ptr, "```", 3 ) == 0 )
    {
        if( ctx.codeBlock )
        {
            ImGui::PopFont();
            ImGui::EndChild();
            ctx.codeBlock = false;
        }
        else
        {
            char tmp[64];
            snprintf( tmp, sizeof( tmp ), "##ollama_code_%d", num );
            ImGui::BeginChild( tmp, ImVec2( 0, 0 ), ImGuiChildFlags_FrameStyle | ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY );
            ImGui::PushFont( m_font );
            ctx.codeBlock = true;
        }
    }
    else
    {
        ImGui::PushTextWrapPos( 0 );
        if( ctx.codeBlock )
        {
            ImGui::TextUnformatted( str.c_str() );
        }
        else if( str == "---" )
        {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
        }
        else if( IsHeading( str.c_str() ) )
        {
            ImGui::PushFont( m_bigFont );
            ImGui::TextUnformatted( str.c_str() );
            ImGui::PopFont();
        }
        else
        {
            const auto begin = str.c_str();
            ptr = begin;
            while( *ptr == ' ' || *ptr == '\t' ) ptr++;
            if( ptr[0] == '*' && ptr[1] == ' ' )
            {
                ImGui::TextUnformatted( std::string( ptr - begin, ' ' ).c_str() );
                ImGui::SameLine();
                ImGui::Bullet();
                ImGui::SameLine();
                ptr++;
            }
            ImGui::TextUnformatted( ptr );
        }
        ImGui::PopTextWrapPos();
    }
}

void TracyLlm::CleanContext( LineContext& ctx)
{
    if( ctx.codeBlock )
    {
        ImGui::PopFont();
        ImGui::EndChild();
    }
}

std::string TracyLlm::HandleToolCalls( const std::string& name, const std::vector<std::string>& args )
{
    if( name == "get_current_time" ) return GetCurrentTime();
    if( name == "fetch_web_page" )
    {
        if( args.empty() ) return "Missing URL argument";
        return FetchWebPage( args[0] );
    }
    if( name == "search_wikipedia" )
    {
        if( args.empty() ) return "Missing search term argument";
        auto query = args[0];
        std::ranges::replace( query, ' ', '+' );
        return FetchWebPage( "https://en.wikipedia.org/w/rest.php/v1/search/page?q=" + query + "&limit=1" );
    }
    if( name == "get_wikipedia" )
    {
        if( args.empty() ) return "Missing page name argument";
        auto res = FetchWebPage( "https://en.wikipedia.org/w/rest.php/v1/page/" + args[0] );
        if( res.size() > 10 * 1024 ) res = res.substr( 0, 10 * 1024 );
        return res;
    }
    return "Unknown tool call: " + name;
}

std::string TracyLlm::GetCurrentTime()
{
    auto t = time( nullptr );
    auto tm = localtime( &t );

    char buffer[64];
    std::strftime( buffer, sizeof( buffer ), "%Y-%m-%d %H:%M:%S", tm );

    return buffer;
}

static size_t WriteFn( void* _data, size_t size, size_t num, void* ptr )
{
    const auto data = (unsigned char*)_data;
    const auto sz = size*num;
    auto& v = *(std::string*)ptr;
    v.append( (const char*)data, sz );
    return sz;
}

std::string TracyLlm::FetchWebPage( const std::string& url )
{
    static bool initialized = false;
    if( !initialized )
    {
        initialized = true;
        curl_global_init( CURL_GLOBAL_ALL );
        atexit( curl_global_cleanup );
    }

    auto curl = curl_easy_init();
    if( !curl ) return "Error: Failed to initialize cURL";

    std::string buf;

    curl_easy_setopt( curl, CURLOPT_URL, url.c_str() );
    curl_easy_setopt( curl, CURLOPT_CA_CACHE_TIMEOUT, 604800L );
    curl_easy_setopt( curl, CURLOPT_FOLLOWLOCATION, 1L );
    curl_easy_setopt( curl, CURLOPT_TIMEOUT, 10 );
    curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, WriteFn );
    curl_easy_setopt( curl, CURLOPT_WRITEDATA, &buf );

    auto res = curl_easy_perform( curl );

    std::string response;
    if( res != CURLE_OK )
    {
        response = "Error: " + std::string( curl_easy_strerror( res ) );
    }
    else
    {
        response = std::move( buf );
    }

    curl_easy_cleanup( curl );
    return response;
}

}
