#include <curl/curl.h>
#include <ollama.hpp>
#include <stdint.h>
#include <stdlib.h>
#include <ranges>

#include "TracyConfig.hpp"
#include "TracyImGui.hpp"
#include "TracyLlm.hpp"
#include "TracyPrint.hpp"
#include "../Fonts.hpp"

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

    static bool initialized = false;
    if( !initialized )
    {
        initialized = true;
        curl_global_init( CURL_GLOBAL_ALL );
        atexit( curl_global_cleanup );
    }

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
        ImGui::PushFont( g_fonts.big );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 - ty ) * 0.5f ) );
        TextCentered( ICON_FA_PLUG_CIRCLE_XMARK );
        TextCentered( "Cannot connect to ollama server!" );
        ImGui::PopFont();
        ImGui::Dummy( ImVec2( 0, ty * 2 ) );
        ImGui::PushFont( g_fonts.small );
        TextCentered( "Server address:" );
        TextCentered( s_config.llmAddress.c_str() );
        ImGui::PopFont();
        ImGui::End();
        return;
    }
    if( IsBusy() )
    {
        ImGui::PushFont( g_fonts.big );
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

    if( !m_models.empty() )
    {
        if( ImGui::Button( ICON_FA_BROOM " Clear chat" ) )
        {
            if( m_responding ) m_stop = true;
            ResetChat();
            m_chatCache.clear();
            *m_input = 0;
        }
        ImGui::SameLine();
    }
    if( ImGui::Button( ICON_FA_ARROWS_ROTATE " Reload models" ) )
    {
        if( m_responding ) m_stop = true;
        m_jobs.emplace_back( WorkItem {
            .task = Task::LoadModels,
            .callback = [this] { UpdateModels(); }
        } );
        m_cv.notify_all();
    }

    if( m_models.empty() )
    {
        ImGui::PushFont( g_fonts.big );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 10 ) * 0.5f ) );
        TextCentered( ICON_FA_WORM );
        ImGui::Spacing();
        TextCentered( "No models available." );
        ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 1.5f ) );
        ImGui::PopFont();
        ImGui::TextWrapped( "You need to retrieve at least one model with the ollama tools before you can use this feature." );
        ImGui::TextWrapped( "Models can be downloaded by running the 'ollama pull <model>' command." );
        ImGui::TextWrapped( "The https://ollama.com/ website contains a list of available models. The 'gemma3' model works quite well." );
        ImGui::End();
        return;
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
                    m_tools.SetModelMaxContext( model.ctxSize );
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

        ImGui::Checkbox( ICON_FA_TEMPERATURE_HALF " Temperature", &m_setTemperature );
        ImGui::SameLine();
        ImGui::SetNextItemWidth( 40 * scale );
        if( ImGui::InputFloat( "##temperature", &m_temperature, 0, 0, "%.2f" ) ) m_temperature = std::clamp( m_temperature, 0.f, 2.f );

        ImGui::Checkbox( ICON_FA_GLOBE " Internet access", &m_tools.m_netAccess );

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
        ImGui::Separator();
        tracy::TextDisabledUnformatted( ICON_FA_TRIANGLE_EXCLAMATION " Context use may be an estimate" );
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
        int cacheIdx = 0;
        int treeIdx = 0;
        int num = 0;
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
            const auto isToolResponse = isUser && line["content"].get_ref<const std::string&>().starts_with( "<tool_output>\n" );

            float diff, offset;
            if( isToolResponse )
            {
                diff = mw - yw;
                offset = diff / 2;
                ImGui::Dummy( ImVec2( offset, 0 ) );
                ImGui::SameLine( 0, 0 );
                ImGui::TextColored( style.Colors[ImGuiCol_TextDisabled], ICON_FA_REPLY );
            }
            else if( isUser )
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
            else
            {
                assert( false );
            }

            ImGui::SameLine( 0, 0 );
            ImGui::Dummy( ImVec2( diff - offset, 0 ) );
            ImGui::SameLine();
            ImGui::BeginGroup();

            if( isToolResponse )
            {
                ImGui::PushStyleColor( ImGuiCol_Text, style.Colors[ImGuiCol_TextDisabled] );
            }
            else if( isUser )
            {
                ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.64f, 0.76f, 0.41f, 1.f ) );
            }
            else if( isError )
            {
                ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 0.25f, 0.25f, 1.f ) );
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
                ImGui::PushID( treeIdx++ );
                auto expand = ImGui::TreeNode( "Tool response..." );
                if( line.contains( "images" ) )
                {
                    ImGui::SameLine();
                    ImGui::TextUnformatted( ICON_FA_FILE_IMAGE );
                }
                if( expand )
                {
                    ImGui::PushFont( g_fonts.mono );
                    ImGui::TextWrapped( "%s", line["content"].get_ref<const std::string&>().c_str() + sizeof( "<tool_output>" ) );
                    ImGui::PopFont();
                    ImGui::TreePop();
                }
                ImGui::PopID();
            }
            else if( isAssistant )
            {
                const auto& content = line["content"].get_ref<const std::string&>();

                auto cit = m_chatCache.find( cacheIdx );
                if( cit == m_chatCache.end() ) cit = m_chatCache.emplace( cacheIdx, ChatCache {} ).first;
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
                            ImGui::PushID( treeIdx++ );
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
                            ImGui::PushID( treeIdx++ );
                            if( ImGui::TreeNode( "Tool query..." ) )
                            {
                                ImGui::PushFont( g_fonts.mono );
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
                PrintMarkdown( line["content"].get_ref<const std::string&>().c_str() );
            }
            ImGui::PopStyleColor();
            ImGui::EndGroup();
            cacheIdx++;
        }

        if( ImGui::GetScrollY() >= ImGui::GetScrollMaxY() )
        {
            ImGui::SetScrollHereY( 1.f );
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
        const char* buttonText = ICON_FA_PAPER_PLANE;
        auto buttonSize = ImGui::CalcTextSize( buttonText );
        buttonSize.x += ImGui::GetStyle().FramePadding.x * 2.0f + ImGui::GetStyle().ItemSpacing.x;
        ImGui::PushItemWidth( ImGui::GetContentRegionAvail().x - buttonSize.x );
        bool send = ImGui::InputTextWithHint( "##ollama_input", "Write your question here...", m_input, InputBufferSize, ImGuiInputTextFlags_EnterReturnsTrue );
        ImGui::SameLine();
        send |= ImGui::Button( buttonText );
        if( send )
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
    if( !m_models.empty() ) m_tools.SetModelMaxContext( m_models[m_modelIdx].ctxSize );
}

void TracyLlm::ResetChat()
{
    auto systemPrompt = std::string( m_systemPrompt->data(), m_systemPrompt->size() );
    systemPrompt += "The current time is: " + m_tools.GetCurrentTime() + "\n";

    m_chat = std::make_unique<ollama::messages>();
    m_chat->emplace_back( ollama::message( "system", systemPrompt ) );
    m_chatId++;
    m_usedCtx = systemPrompt.size() / 4;
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
        if( m_setTemperature ) req["options"]["temperature"] = m_temperature;

        res = m_ollama->chat( req, [this]( const ollama::response& response ) -> bool { return OnResponse( response ); });
    }
    catch( std::exception& e )
    {
        m_lock.lock();
        if( !m_chat->empty() && m_chat->back()["role"].get_ref<const std::string&>() == "assistant" ) m_chat->pop_back();
        m_chat->emplace_back( ollama::message( "error", e.what() ) );
        m_responding = false;
        m_stop = false;
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
    std::unique_lock lock( m_lock );

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
                    lock.unlock();
                    const auto reply = m_tools.HandleToolCalls( tool, lines );
                    const auto output = "<tool_output>\n" + reply.reply;
                    lock.lock();
                    if( reply.image.empty() )
                    {
                        m_chat->emplace_back( ollama::message( "user", output ) );
                    }
                    else
                    {
                        std::vector<ollama::image> images;
                        images.emplace_back( ollama::image::from_base64_string( reply.image ) );
                        m_chat->emplace_back( ollama::message( "user", output, images ) );
                    }

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
            if( ptr[3] )
            {
                ImGui::PushFont( g_fonts.small );
                ImGui::SetCursorPosX( ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize( ptr + 3 ).x );
                ImGui::TextUnformatted( ptr + 3 );
                ImGui::PopFont();
            }
            ImGui::PushFont( g_fonts.mono );
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
            ImGui::PushFont( g_fonts.big );
            ImGui::TextUnformatted( str.c_str() );
            ImGui::PopFont();
        }
        else
        {
            const auto begin = str.c_str();
            ptr = begin;
            while( *ptr == ' ' || *ptr == '\t' ) ptr++;
            if( ( ptr[0] == '*' || ptr[0] == '-' ) && ptr[1] == ' ' )
            {
                ImGui::TextUnformatted( std::string( ptr - begin, ' ' ).c_str() );
                ImGui::SameLine();
                ImGui::Bullet();
                ImGui::SameLine();
                ptr++;
            }
            PrintMarkdown( ptr );
        }
        ImGui::PopTextWrapPos();
    }
}

void TracyLlm::PrintMarkdown( const char* str )
{
    auto& style = ImGui::GetStyle();
    ImGui::PushStyleVar( ImGuiStyleVar_ItemSpacing, ImVec2( style.ItemSpacing.x, 0.0f ) );

    auto end = str + strlen( str );
    bool first = true;
    bool isCode = false;

    while( str != end )
    {
        if( first )
        {
            first = false;
        }
        else
        {
            ImGui::SameLine( 0, 0 );
        }

        auto next = str;
        while( next != end && *next != '`' ) next++;
        if( *next == '`' )
        {
            PrintTextWrapped( str, next );
            str = next + 1;

            isCode = !isCode;
            if( isCode )
            {
                ImGui::PushFont( g_fonts.mono );
            }
            else
            {
                ImGui::PopFont();
            }
        }
        else
        {
            PrintTextWrapped( str, next );
            str = next;
        }
    }

    if( isCode ) ImGui::PopFont();

    ImGui::PopStyleVar();
    ImGui::SetCursorPosY( ImGui::GetCursorPosY() + style.ItemSpacing.y );
}

void TracyLlm::CleanContext( LineContext& ctx)
{
    if( ctx.codeBlock )
    {
        ImGui::PopFont();
        ImGui::EndChild();
    }
}

}
