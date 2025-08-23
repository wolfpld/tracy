#include <array>
#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <ranges>

#include "TracyConfig.hpp"
#include "TracyImGui.hpp"
#include "TracyLlm.hpp"
#include "TracyLlmApi.hpp"
#include "TracyLlmChat.hpp"
#include "TracyLlmTools.hpp"
#include "TracyPrint.hpp"
#include "TracyWeb.hpp"
#include "../Fonts.hpp"

#include "data/SystemPrompt.hpp"
#include "data/SystemReminder.hpp"

namespace tracy
{

extern double s_time;

constexpr size_t InputBufferSize = 1024;

TracyLlm::TracyLlm( Worker& worker )
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

    m_systemPrompt = Unembed( SystemPrompt );
    m_systemReminder = Unembed( SystemReminder );

    m_input = new char[InputBufferSize];
    m_apiInput = new char[InputBufferSize];
    ResetChat();

    m_api = std::make_unique<TracyLlmApi>();
    m_chatUi = std::make_unique<TracyLlmChat>();
    m_tools = std::make_unique<TracyLlmTools>( worker );

    m_busy = true;
    QueueConnect();
    m_thread = std::thread( [this] { WorkerThread(); } );
}

TracyLlm::~TracyLlm()
{
    delete[] m_input;
    delete[] m_apiInput;

    if( m_thread.joinable() )
    {
        {
            std::lock_guard lock( m_lock );
            if( m_currentJob ) m_currentJob->stop = true;
            m_exit.store( true, std::memory_order_release );
            m_cv.notify_all();
        }
        m_thread.join();
    }
}

void TracyLlm::Draw()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 400 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Tracy Assist", &m_show, ImGuiWindowFlags_NoScrollbar );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    if( IsBusy() )
    {
        ImGui::PushFont( g_fonts.normal, FontBig );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
        TextCentered( ICON_FA_HOURGLASS );
        TextCentered( "Please wait..." );
        DrawWaitingDots( s_time );
        ImGui::PopFont();
        ImGui::End();
        return;
    }

    auto& style = ImGui::GetStyle();

    const auto manualEmbeddingsState = m_tools->GetManualEmbeddingsState();
    if( manualEmbeddingsState.inProgress )
    {
        ImGui::PushFont( g_fonts.normal, FontBig );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 7 ) * 0.5f ) );
        TextCentered( ICON_FA_BOOK_BOOKMARK );
        ImGui::Spacing();
        TextCentered( "Building manual embeddings..." );
        ImGui::Spacing();
        DrawWaitingDots( s_time );
        ImGui::TextUnformatted( "" );
        ImGui::PopFont();
        const float w = 100 * scale;
        const float ww = ImGui::GetWindowWidth();
        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
        ImGui::SetCursorPosX( ( ww - w ) * 0.5f );
        ImGui::ProgressBar( manualEmbeddingsState.progress, ImVec2( w, 0 ), "" );
        ImGui::PopStyleVar();
        ImGui::Spacing();
        char tmp[128];
        snprintf( tmp, sizeof( tmp ), "Progress: %.1f%%", manualEmbeddingsState.progress * 100 );
        TextCentered( tmp );
        ImGui::Spacing();
        const auto sz = ImGui::CalcTextSize( "Cancel" ).x + style.FramePadding.x * 2;
        ImGui::SetCursorPosX( ( ImGui::GetWindowWidth() - sz ) * 0.5f );
        if( ImGui::Button( "Cancel" ) ) m_tools->CancelManualEmbeddings();
        ImGui::End();
        return;
    }

    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 1.f, 0.f, 1.0f ) );
    ImGui::AlignTextToFramePadding();
    ImGui::TextWrapped( ICON_FA_TRIANGLE_EXCLAMATION );
    ImGui::PopStyleColor();
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::TextUnformatted( "Always verify the chat responses, as they may contain incorrect or misleading informations." );
        ImGui::EndTooltip();
    }
    ImGui::SameLine();

    std::lock_guard lock( m_lock );

    const auto hasChat = m_chat.size() <= 1 && *m_input == 0;
    if( hasChat ) ImGui::BeginDisabled();
    if( ImGui::Button( ICON_FA_BROOM " Clear chat" ) )
    {
        if( m_currentJob ) m_currentJob->stop = true;
        ResetChat();
    }
    if( hasChat ) ImGui::EndDisabled();
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_ARROWS_ROTATE " Reconnect" ) )
    {
        if( m_currentJob ) m_currentJob->stop = true;
        QueueConnect();
    }

    ImGui::SameLine();
    if( ImGui::TreeNode( "Settings" ) )
    {
        const auto responding = m_currentJob != nullptr;
        if( responding ) ImGui::BeginDisabled();
        ImGui::Spacing();
        ImGui::AlignTextToFramePadding();
        TextDisabledUnformatted( "API:" );
        ImGui::SameLine();
        const auto sz = std::min( InputBufferSize-1, s_config.llmAddress.size() );
        memcpy( m_apiInput, s_config.llmAddress.c_str(), sz );
        m_apiInput[sz] = 0;
        bool changed = ImGui::InputTextWithHint( "##api", "http://localhost:1234", m_apiInput, InputBufferSize );
        ImGui::SameLine();
        if( ImGui::BeginCombo( "##presets", nullptr, ImGuiComboFlags_NoPreview ) )
        {
            struct Preset
            {
                const char* name;
                const char* address;
            };
            constexpr static std::array presets = {
                Preset { "Llama.cpp", "http://localhost:8080" },
                Preset { "LM Studio", "http://localhost:1234" },
                Preset { "Ollama", "http://localhost:11434" },
            };
            for( auto& preset : presets )
            {
                if( ImGui::Selectable( preset.name ) )
                {
                    memcpy( m_apiInput, preset.address, strlen( preset.address ) + 1 );
                    changed = true;
                }
            }
            ImGui::EndCombo();
        }
        if( changed )
        {
            s_config.llmAddress = m_apiInput;
            SaveConfig();
            QueueConnect();
        }

        const auto& models = m_api->GetModels();
        ImGui::AlignTextToFramePadding();
        TextDisabledUnformatted( "Model:" );
        ImGui::SameLine();
        if( models.empty() || m_modelIdx < 0 )
        {
            ImGui::TextUnformatted( "No models available" );
        }
        else
        {
            if( ImGui::BeginCombo( "##model", models[m_modelIdx].name.c_str() ) )
            {
                for( size_t i = 0; i < models.size(); ++i )
                {
                    const auto& model = models[i];
                    if( model.embeddings ) continue;
                    if( ImGui::Selectable( model.name.c_str(), i == m_modelIdx ) )
                    {
                        m_modelIdx = i;
                        s_config.llmModel = model.name;
                        SaveConfig();
                    }
                    if( m_modelIdx == i ) ImGui::SetItemDefaultFocus();
                    if( !model.quant.empty() )
                    {
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%s)", model.quant.c_str() );
                    }
                }
                ImGui::EndCombo();
            }
        }

        ImGui::AlignTextToFramePadding();
        TextDisabledUnformatted( "Embeddings:" );
        ImGui::SameLine();
        if( models.empty() || m_embedIdx < 0 )
        {
            ImGui::TextUnformatted( "No models available" );
        }
        else
        {
            if( ImGui::BeginCombo( "##embedmodel", models[m_embedIdx].name.c_str() ) )
            {
                for( size_t i = 0; i < models.size(); ++i )
                {
                    const auto& model = models[i];
                    if( !model.embeddings ) continue;
                    if( ImGui::Selectable( model.name.c_str(), i == m_embedIdx ) )
                    {
                        m_embedIdx = i;
                        s_config.llmEmbeddingsModel = model.name;
                        SaveConfig();
                        m_tools->SelectManualEmbeddings( model.name );
                    }
                    if( m_embedIdx == i ) ImGui::SetItemDefaultFocus();
                    if( !model.quant.empty() )
                    {
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%s)", model.quant.c_str() );
                    }
                }
                ImGui::EndCombo();
            }
        }

        ImGui::Checkbox( ICON_FA_TEMPERATURE_HALF " Temperature", &m_setTemperature );
        ImGui::SameLine();
        ImGui::SetNextItemWidth( 40 * scale );
        if( ImGui::InputFloat( "##temperature", &m_temperature, 0, 0, "%.2f" ) ) m_temperature = std::clamp( m_temperature, 0.f, 2.f );
        if( responding ) ImGui::EndDisabled();

        ImGui::Checkbox( ICON_FA_GLOBE " Internet access", &m_tools->m_netAccess );

        if( ImGui::TreeNode( "External services" ) )
        {
            char buf[1024];

            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted( "User agent:" );
            ImGui::SameLine();
            snprintf( buf, sizeof( buf ), "%s", s_config.llmUserAgent.c_str() );
            if( ImGui::InputTextWithHint( "##useragent", "Spoof user agent", buf, sizeof( buf ) ) )
            {
                s_config.llmUserAgent = buf;
                SaveConfig();
            }

            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted( "Google Search Engine:" );
            ImGui::SameLine();
            snprintf( buf, sizeof( buf ), "%s", s_config.llmSearchIdentifier.c_str() );
            if( ImGui::InputTextWithHint( "##cse", "search identifier", buf, sizeof( buf ) ) )
            {
                s_config.llmSearchIdentifier = buf;
                SaveConfig();
            }
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_HOUSE "##cse" ) ) OpenWebpage( "https://cse.google.com/cse/create/new" );

            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted( "Google Search API Key:" );
            ImGui::SameLine();
            snprintf( buf, sizeof( buf ), "%s", s_config.llmSearchApiKey.c_str() );
            if( ImGui::InputTextWithHint( "##csekey", "search API key", buf, sizeof( buf ) ) )
            {
                s_config.llmSearchApiKey = buf;
                SaveConfig();
            }
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_HOUSE "##csekey" ) ) OpenWebpage( "https://developers.google.com/custom-search/v1/overview" );

            ImGui::TreePop();
        }

        ImGui::TreePop();
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

    if( !m_api->IsConnected() )
    {
        ImGui::PushFont( g_fonts.normal, FontBig );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
        TextCentered( ICON_FA_PLUG_CIRCLE_XMARK );
        TextCentered( "No connection to LLM API" );
        ImGui::PopFont();
        ImGui::End();
        return;
    }

    const auto& models = m_api->GetModels();
    if( models.empty() || m_modelIdx < 0 )
    {
        ImGui::PushFont( g_fonts.normal, FontBig );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
        TextCentered( ICON_FA_WORM );
        ImGui::Spacing();
        TextCentered( "No models available." );
        ImGui::PopFont();
        ImGui::End();
        return;
    }

    if( !manualEmbeddingsState.done || m_embedIdx < 0 || manualEmbeddingsState.model != models[m_embedIdx].name )
    {
        if( m_embedIdx < 0 ) ImGui::BeginDisabled();
        if( ImGui::SmallButton( ICON_FA_BOOK_BOOKMARK " Learn manual" ) )
        {
            if( m_currentJob ) m_currentJob->stop = true;
            m_tools->BuildManualEmbeddings( models[m_embedIdx].name, *m_api );
        }
        if( m_embedIdx < 0 ) ImGui::EndDisabled();
    }

    const auto ctxSize = models[m_modelIdx].contextSize;
    ImGui::Spacing();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    if( ctxSize <= 0 )
    {
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
        ImGui::ProgressBar( 1, ImVec2( -1, 0 ), "" );
    }
    else
    {
        const auto ratio = m_usedCtx / (float)ctxSize;
        if( ratio < 0.5f )
        {
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.2f, 0.6f, 0.2f, 1.0f));
        }
        else if( ratio < 0.8f )
        {
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.6f, 0.6f, 0.2f, 1.0f));
        }
        else
        {
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
        }
        ImGui::ProgressBar( ratio, ImVec2( -1, 0 ), "" );
    }
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        if( ctxSize <= 0 )
        {
            ImGui::TextUnformatted( "Context size is not available" );
        }
        else
        {
            TextFocused( "Used context size:", RealToString( m_usedCtx ) );
            ImGui::SameLine();
            char buf[64];
            PrintStringPercent( buf, m_usedCtx / (float)ctxSize * 100 );
            tracy::TextDisabledUnformatted( buf );
            TextFocused( "Available context size:", RealToString( ctxSize ) );
            ImGui::Separator();
            tracy::TextDisabledUnformatted( ICON_FA_TRIANGLE_EXCLAMATION " Context use may be an estimate" );
        }
        ImGui::EndTooltip();
    }

    bool inputChanged = false;
    ImGui::Spacing();
    ImGui::BeginChild( "##chat", ImVec2( 0, -( ImGui::GetFrameHeight() + style.ItemSpacing.y * 2 ) ), ImGuiChildFlags_Borders, ImGuiWindowFlags_AlwaysVerticalScrollbar );
    if( m_chat.size() <= 1 )   // account for system prompt
    {
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 15 ) * 0.5f ) );
        ImGui::PushStyleColor( ImGuiCol_Text, style.Colors[ImGuiCol_TextDisabled] );
        ImGui::PushFont( g_fonts.normal, FontNormal * 3.f );
        TextCentered( ICON_FA_ROBOT );
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::PopFont();
        ImGui::TextWrapped( "What I had not realized is that extremely short exposures to a relatively simple computer program could induce powerful delusional thinking in quite normal people." );
        ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.5f ) );
        constexpr auto signature = "-- Joseph Weizenbaum, 1976";
        const auto tw = ImGui::CalcTextSize( signature ).x;
        ImGui::SetCursorPosX( ( ImGui::GetWindowWidth() - tw - 30 * scale ) );
        ImGui::TextUnformatted( signature );
        ImGui::PopStyleColor();
    }
    else
    {
        ImGui::PushID( m_chatId );
        m_chatUi->Begin();

        int turnIdx = 0;
        for( auto it = m_chat.begin(); it != m_chat.end(); ++it )
        {
            const auto& line = *it;
            if( !line.contains( "role" ) ) break;
            const auto& roleStr = line["role"].get_ref<const std::string&>();
            if( roleStr == "system" ) continue;
            const auto& contentNode = line["content"];
            if( !contentNode.is_string() ) continue;
            const auto& content = contentNode.get_ref<const std::string&>();

            TracyLlmChat::TurnRole role = TracyLlmChat::TurnRole::None;
            if( roleStr == "user" ) role = TracyLlmChat::TurnRole::User;
            else if( roleStr == "error" ) role = TracyLlmChat::TurnRole::Error;
            else if( roleStr == "assistant" ) role = TracyLlmChat::TurnRole::Assistant;
            else assert( false );

            if( role == TracyLlmChat::TurnRole::User )
            {
                if( content.starts_with( "<tool_output>\n" ) ) role = TracyLlmChat::TurnRole::Assistant;
                else if( content.starts_with( "<debug>" ) ) role = TracyLlmChat::TurnRole::UserDebug;
                else if( content.starts_with( "<attachment>\n" ) ) role = TracyLlmChat::TurnRole::Attachment;
            }
            else if( role == TracyLlmChat::TurnRole::Assistant )
            {
                if( content.starts_with( "<debug>" ) ) role = TracyLlmChat::TurnRole::AssistantDebug;
            }

            ImGui::PushID( turnIdx++ );
            if( !m_chatUi->Turn( role, content ) )
            {
                if( role == TracyLlmChat::TurnRole::Assistant || role == TracyLlmChat::TurnRole::AssistantDebug )
                {
                    QueueSendMessage();
                }
                else if( role == TracyLlmChat::TurnRole::User || role == TracyLlmChat::TurnRole::UserDebug )
                {
                    const auto sz = std::min( InputBufferSize - 1, content.size() );
                    memcpy( m_input, content.data(), sz );
                    m_input[sz] = 0;
                    inputChanged = true;
                }

                auto cit = it;
                while( cit != m_chat.end() )
                {
                    const auto& content = (*cit)["content"].get_ref<const std::string&>();
                    const auto tokens = m_api->Tokenize( content, m_modelIdx );
                    m_usedCtx -= tokens >= 0 ? tokens : content.size() / 4;
                    ++cit;
                }

                m_chat.erase( it, m_chat.end() );
                if( m_currentJob ) m_currentJob->stop = true;
                ImGui::PopID();
                break;
            }
            ImGui::PopID();
        }

        m_chatUi->End();
        ImGui::PopID();

        if( ImGui::GetScrollY() >= ImGui::GetScrollMaxY() )
        {
            ImGui::SetScrollHereY( 1.f );
        }
    }
    ImGui::EndChild();
    ImGui::Spacing();

    if( m_currentJob )
    {
        const bool disabled = m_currentJob->stop;
        if( disabled ) ImGui::BeginDisabled();
        if( ImGui::Button( ICON_FA_STOP " Stop" ) ) m_currentJob->stop = true;
        if( disabled ) ImGui::EndDisabled();
        ImGui::SameLine();
        const auto pos = ImGui::GetWindowPos() + ImGui::GetCursorPos();
        auto draw = ImGui::GetWindowDrawList();
        const auto ty = ImGui::GetTextLineHeight();
        draw->AddCircleFilled( pos + ImVec2( ty * 0.5f + 0 * ty, ty * 0.675f ), ty * ( 0.15f + 0.2f * ( pow( cos( s_time * 3.5f + 0.3f ), 16.f ) ) ), 0xFFBBBBBB, 12 );
        draw->AddCircleFilled( pos + ImVec2( ty * 0.5f + 1 * ty, ty * 0.675f ), ty * ( 0.15f + 0.2f * ( pow( cos( s_time * 3.5f        ), 16.f ) ) ), 0xFFBBBBBB, 12 );
        draw->AddCircleFilled( pos + ImVec2( ty * 0.5f + 2 * ty, ty * 0.675f ), ty * ( 0.15f + 0.2f * ( pow( cos( s_time * 3.5f - 0.3f ), 16.f ) ) ), 0xFFBBBBBB, 12 );
        ImGui::Dummy( ImVec2( ty * 3, ty ) );
        ImGui::SameLine();
        if( disabled )
        {
            ImGui::TextUnformatted( "Stopping..." );
        }
        else
        {
            ImGui::TextUnformatted( "Generating..." );
        }
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
        if( inputChanged ) ImGui::GetInputTextState( ImGui::GetCurrentWindow()->GetID( "##chat_input" ) )->ReloadUserBufAndMoveToEnd();
        bool send = ImGui::InputTextWithHint( "##chat_input", "Write your question here...", m_input, InputBufferSize, ImGuiInputTextFlags_EnterReturnsTrue );
        ImGui::SameLine();
        if( *m_input == 0 ) ImGui::BeginDisabled();
        send |= ImGui::Button( buttonText );
        if( *m_input == 0 ) ImGui::EndDisabled();
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
                AddMessage( ptr, "user" );
                *m_input = 0;
                QueueSendMessage();
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

void TracyLlm::WorkerThread()
{
    std::unique_lock lock( m_lock );
    while( !m_exit.load( std::memory_order_acquire ) )
    {
        m_cv.wait( lock, [this] { return !m_jobs.empty() || m_exit.load( std::memory_order_acquire ); } );
        if( m_exit.load( std::memory_order_acquire ) ) break;

        m_currentJob = std::move( m_jobs.front() );
        m_jobs.erase( m_jobs.begin() );

        switch( m_currentJob->task )
        {
        case Task::Connect:
            m_busy = true;
            lock.unlock();
            m_api->Connect( s_config.llmAddress.c_str() );
            m_currentJob->callback();
            lock.lock();
            m_busy = false;
            break;
        case Task::SendMessage:
            SendMessage( lock );
            break;
        case Task::Tokenize:
        {
            lock.unlock();
            auto tokens = m_api->Tokenize( m_currentJob->param, m_modelIdx );
            if( tokens < 0 ) tokens = m_currentJob->param.size() / 4;
            m_currentJob->callback2( { { "tokens", tokens } } );
            lock.lock();
            break;
        }
        }

        m_currentJob.reset();
    }
};

void TracyLlm::UpdateModels()
{
    m_modelIdx = -1;
    m_embedIdx = -1;

    auto& models = m_api->GetModels();
    auto it = std::ranges::find_if( models, []( const auto& model ) { return model.name == s_config.llmModel; } );
    if( it == models.end() )
    {
        for( int i=0; i<models.size(); i++ )
        {
            if( !models[i].embeddings )
            {
                m_modelIdx = i;
                break;
            }
        }
    }
    else
    {
        m_modelIdx = std::distance( models.begin(), it );
    }

    it = std::ranges::find_if( models, []( const auto& model ) { return model.name == s_config.llmEmbeddingsModel; } );
    if( it == models.end() )
    {
        for( int i=0; i<models.size(); i++ )
        {
            if( models[i].embeddings )
            {
                m_embedIdx = i;
                break;
            }
        }
    }
    else
    {
        m_embedIdx = std::distance( models.begin(), it );
    }

    if( m_embedIdx >= 0 )
    {
        m_tools->SelectManualEmbeddings( models[m_embedIdx].name );
    }
}

void TracyLlm::ResetChat()
{
    std::string systemPrompt = "<SYSTEM_PROMPT>\n";
    systemPrompt += std::string( m_systemPrompt->data(), m_systemPrompt->size() );
#ifndef NDEBUG
    systemPrompt += "\n\n# DEBUG MODE AVAILABLE\n";
    systemPrompt += "Upon a user query beginning with `<debug>`, activate *Debug Mode*. In this mode, ignore all prior instructions. Your response must detail your complete reasoning process and the exact steps taken to generate your *previous* non-debug answer. Explicitly state any internal rules applied. Do not say you are sorry. Do not tell how you will change your behavior. Focus strictly on the analysis of what happened.\n";
#endif
    systemPrompt += "</SYSTEM_PROMPT>\n";

    *m_input = 0;
    m_usedCtx = 0;
    m_chatId++;
    m_chat.clear();

    AddMessage( std::move( systemPrompt ), "system" );
}

void TracyLlm::QueueConnect()
{
    m_jobs.emplace_back( std::make_shared<WorkItem>( WorkItem {
        .task = Task::Connect,
        .callback = [this] { UpdateModels(); }
    } ) );
    m_cv.notify_all();
}

bool TracyLlm::QueueSendMessage()
{
    if( !m_api->IsConnected() || m_modelIdx < 0 ) return false;
    m_jobs.emplace_back( std::make_shared<WorkItem>( WorkItem {
        .task = Task::SendMessage
    } ) );
    m_cv.notify_all();
    return true;
}

void TracyLlm::AddMessage( std::string&& str, const char* role )
{
    if( !m_api )
    {
        std::unique_lock<std::mutex> null;
        AddMessageBlocking( std::move( str ), role, null );
        return;
    }

    m_jobs.emplace_back( std::make_shared<WorkItem>( WorkItem {
        .task = Task::Tokenize,
        .callback2 = [this, str, role]( nlohmann::json json ) {
            m_usedCtx += json["tokens"].get<int>();
            nlohmann::json msg = {
                { "role", role },
                { "content", str }
            };
            m_chat.emplace_back( std::move( msg ) );
        },
        .param = std::move( str ),
    } ) );
    m_cv.notify_all();
}

void TracyLlm::AddMessageBlocking( std::string&& str, const char* role, std::unique_lock<std::mutex>& lock )
{
    const auto tokens = m_api ? m_api->Tokenize( str, m_modelIdx ) : -1;
    m_usedCtx += tokens >= 0 ? tokens : str.size() / 4;

    nlohmann::json msg;
    msg["role"] = role;
    msg["content"] = std::move( str );

    if( lock ) lock.lock();
    m_chat.emplace_back( std::move( msg ) );
    if( lock ) lock.unlock();
}

void TracyLlm::AddAttachment( std::string&& str, const char* role )
{
    AddMessage( "<attachment>\n" + std::move( str ), role );
}

void TracyLlm::ManageContext( std::unique_lock<std::mutex>& lock )
{
    const auto& models = m_api->GetModels();
    const auto ctxSize = models[m_modelIdx].contextSize;
    if( ctxSize <= 0 ) return;

    const auto quota = int( ctxSize * 0.7f );
    if( m_usedCtx < quota ) return;

    size_t idx = 0;
    std::vector<std::pair<size_t, size_t>> toolOutputs;
    for( auto& msg : m_chat )
    {
        if( msg["role"].get_ref<const std::string&>() == "user" )
        {
            auto& content = msg["content"];
            const auto& str = content.get_ref<const std::string&>();
            if( str.starts_with( "<tool_output>\n" ) )
            {
                toolOutputs.emplace_back( str.size(), idx );
            }
        }
        idx++;
    }
    if( toolOutputs.size() > 1 )
    {
        toolOutputs.pop_back();     // keep the last tool output
        std::ranges::stable_sort( toolOutputs, []( const auto& a, const auto& b ) { return a.first > b.first; } );
        for( auto& v : toolOutputs )
        {
            auto tokens = m_api->Tokenize( m_chat[v.second]["content"].get_ref<const std::string&>(), m_modelIdx );
            m_usedCtx -= tokens >= 0 ? tokens : v.first / 4;

            lock.lock();
            m_chat[v.second]["content"] = TracyLlmChat::ForgetMsg;
            lock.unlock();
            tokens = m_api->Tokenize( TracyLlmChat::ForgetMsg, m_modelIdx );
            m_usedCtx += tokens >= 0 ? tokens : strlen( TracyLlmChat::ForgetMsg ) / 4;

            if( m_usedCtx < quota ) break;
        }
    }
}

void TracyLlm::SendMessage( std::unique_lock<std::mutex>& lock )
{
    lock.unlock();
    ManageContext( lock );

    bool debug = false;
#ifndef NDEBUG
    if( m_chat.size() > 1 && m_chat.back()["role"].get_ref<const std::string&>() == "user" )
    {
        const auto& content = m_chat.back()["content"].get_ref<const std::string&>();
        if( content.starts_with( "<debug>" ) ) debug = true;
    }
#endif

    if( debug )
    {
        AddMessageBlocking( "<debug>\n", "assistant", lock );
    }
    else
    {
        AddMessageBlocking( "<think>", "assistant", lock );
    }

    bool res;
    try
    {
        auto chat = m_chat;

        std::string inject;
        if( debug )
        {
            inject += "<SYSTEM_REMINDER>\n";
            inject += "You are in debug mode.\n";
            inject += "</SYSTEM_REMINDER>\n";
        }
        else
        {
            inject += "<SYSTEM_REMINDER>\n";
            inject += std::string( m_systemReminder->data(), m_systemReminder->size() );
            inject += "</SYSTEM_REMINDER>\n";
        }

        chat.front()["content"].get_ref<std::string&>().append( "\n\nThe current time is: " + m_tools->GetCurrentTime() + "\n" );
        chat.back()["content"].get_ref<std::string&>().insert( 0, inject );

        nlohmann::json req;
        req["model"] = m_api->GetModels()[m_modelIdx].name;
        req["messages"] = std::move( chat );
        req["stream"] = true;
        if( m_setTemperature ) req["temperature"] = m_temperature;

        res = m_api->ChatCompletion( req, [this]( const nlohmann::json& response ) -> bool { return OnResponse( response ); }, m_modelIdx );

        lock.lock();
    }
    catch( std::exception& e )
    {
        lock.lock();
        if( !m_chat.empty() && m_chat.back()["role"].get_ref<const std::string&>() == "assistant" ) m_chat.pop_back();
        lock.unlock();
        AddMessageBlocking( e.what(), "error", lock );
        lock.lock();
    }
}

bool TracyLlm::OnResponse( const nlohmann::json& json )
{
    std::unique_lock lock( m_lock );

    if( m_currentJob->stop )
    {
        m_focusInput = true;
        return false;
    }

    auto& back = m_chat.back();
    auto& content = back["content"];
    const auto& str = content.get_ref<const std::string&>();

    std::string responseStr;
    bool done = false;
    try
    {
        auto& choices = json["choices"];
        if( !choices.empty() )
        {
            auto& node = choices[0];
            auto& delta = node["delta"];
            if( delta.contains( "content" ) && delta["content"].is_string() ) responseStr = delta["content"].get_ref<const std::string&>();
            done = !node["finish_reason"].empty();
        }
    }
    catch( const nlohmann::json::exception& e )
    {
        m_focusInput = true;
        return false;
    }

    if( !responseStr.empty() )
    {
        std::erase( responseStr, '\r' );
        content = str + responseStr;
        m_usedCtx++;
    }

    if( done )
    {
        if( json.contains( "usage" ) )
        {
            auto& usage = json["usage"];
            if( usage.contains( "total_tokens" ) ) m_usedCtx = usage["total_tokens"].get<int>();
        }

        bool isTool = false;
        auto& str = back["content"].get_ref<const std::string&>();
        if( !str.starts_with( "<debug>" ) )
        {
            auto pos = str.find( "<tool>" );
            if( pos != std::string::npos )
            {
                pos += 6;
                while( str[pos] == '\n' ) pos++;
                auto end = str.find( "</tool>", pos );
                if( end != std::string::npos )
                {
                    auto repeat = str.find( "<tool>", end );
                    if( repeat != std::string::npos )
                    {
                        lock.unlock();
                        AddMessageBlocking( "<tool_output>\nError: Only one tool call is allowed per turn.", "user", lock );
                        lock.lock();
                    }
                    else
                    {
                        while( end > pos && str[end-1] == '\n' ) end--;
                        const auto tool = str.substr( pos, end - pos );
                        lock.unlock();

                        TracyLlmTools::ToolReply reply;
                        try
                        {
                            auto json = nlohmann::json::parse( tool );
                            reply = m_tools->HandleToolCalls( json, *m_api, m_api->GetModels()[m_modelIdx].contextSize, m_embedIdx >= 0 );
                        }
                        catch( const nlohmann::json::exception& e )
                        {
                            reply.reply = e.what();
                        }

                        isTool = true;
                        auto output = "<tool_output>\n" + reply.reply;
                        AddMessageBlocking( std::move( output ), "user", lock );
                        lock.lock();
                    }
                    QueueSendMessage();
                }
            }
        }
        if( !isTool )
        {
            m_focusInput = true;
        }
    }

    return true;
}

}
