#include <array>
#include <cmath>
#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>

#include "TracyConfig.hpp"
#include "TracyImGui.hpp"
#include "TracyLlm.hpp"
#include "TracyLlmApi.hpp"
#include "TracyLlmChat.hpp"
#include "TracyLlmTools.hpp"
#include "TracyPrint.hpp"
#include "TracyWeb.hpp"
#include "TracyWorker.hpp"
#include "../Fonts.hpp"
#include "../public/common/TracySystem.hpp"

#include "data/SystemPrompt.hpp"
#include "data/ToolsJson.hpp"

namespace tracy
{

extern double s_time;

constexpr size_t InputBufferSize = 1024;

TracyLlm::TracyLlm( Worker& worker, View& view, const TracyManualData& manual )
    : m_exit( false )
    , m_input( nullptr )
    , m_apiInput( nullptr )
    , m_worker( worker )
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
    auto toolsJson = Unembed( ToolsJson );
    m_toolsJson = nlohmann::json::parse( toolsJson->data(), toolsJson->data() + toolsJson->size() );

    m_input = new char[InputBufferSize];
    m_apiInput = new char[InputBufferSize];
    ResetChat();

    m_api = std::make_unique<TracyLlmApi>();
    m_chatUi = std::make_unique<TracyLlmChat>( view, worker );
    m_tools = std::make_unique<TracyLlmTools>( worker, manual );

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
            std::lock_guard lock( m_jobsLock );
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
        TextCentered( "Please wait…" );
        DrawWaitingDotsCentered( s_time );
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
        TextCentered( "Building manual embeddings…" );
        ImGui::Spacing();
        DrawWaitingDotsCentered( s_time );
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

    std::lock_guard lock( m_chatLock );

    const auto hasChat = m_chat.size() <= 1 && *m_input == 0;
    if( hasChat ) ImGui::BeginDisabled();
    if( ImGui::Button( ICON_FA_BROOM " Clear chat" ) )
    {
        m_jobsLock.lock();
        if( m_currentJob ) m_currentJob->stop = true;
        m_jobsLock.unlock();
        ResetChat();
    }
    if( hasChat ) ImGui::EndDisabled();
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_ARROWS_ROTATE " Reconnect" ) )
    {
        std::lock_guard lock( m_jobsLock );
        if( m_currentJob ) m_currentJob->stop = true;
        QueueConnect();
    }

    ImGui::SameLine();
    if( ImGui::TreeNode( "Settings" ) )
    {
        m_jobsLock.lock();
        const auto responding = m_currentJob != nullptr;
        m_jobsLock.unlock();
        if( responding ) ImGui::BeginDisabled();
        ImGui::Spacing();
        ImGui::AlignTextToFramePadding();
        TextDisabledUnformatted( "API:" );
        ImGui::SameLine();
        const auto sz = std::min( InputBufferSize-1, s_config.llmAddress.size() );
        memcpy( m_apiInput, s_config.llmAddress.c_str(), sz );
        m_apiInput[sz] = 0;
        ImGui::SetNextItemWidth( ImGui::GetContentRegionAvail().x - ImGui::GetFrameHeight() - ImGui::GetStyle().ItemSpacing.x );
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
            std::lock_guard lock( m_jobsLock );
            QueueConnect();
        }

        const auto& models = m_api->GetModels();
        ImGui::AlignTextToFramePadding();
        TextDisabledUnformatted( ICON_FA_COMMENTS " Chat model:" );
        ImGui::SameLine();
        if( models.empty() || m_modelIdx < 0 )
        {
            ImGui::TextUnformatted( "No models available" );
        }
        else
        {
            ImGui::SetNextItemWidth( ImGui::GetContentRegionAvail().x );
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
        TextDisabledUnformatted( ICON_FA_BOLT_LIGHTNING " Fast model:" );
        ImGui::SameLine();
        if( models.empty() || m_fastIdx < 0 )
        {
            ImGui::TextUnformatted( "No models available" );
        }
        else
        {
            ImGui::SetNextItemWidth( ImGui::GetContentRegionAvail().x );
            if( ImGui::BeginCombo( "##fastmodel", models[m_fastIdx].name.c_str() ) )
            {
                for( size_t i = 0; i < models.size(); ++i )
                {
                    const auto& model = models[i];
                    if( model.embeddings ) continue;
                    if( ImGui::Selectable( model.name.c_str(), i == m_fastIdx ) )
                    {
                        m_fastIdx = i;
                        s_config.llmFastModel = model.name;
                        SaveConfig();
                    }
                    if( m_fastIdx == i ) ImGui::SetItemDefaultFocus();
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
        TextDisabledUnformatted( ICON_FA_BOOK_BOOKMARK " Embeddings model:" );
        ImGui::SameLine();
        if( models.empty() || m_embedIdx < 0 )
        {
            ImGui::TextUnformatted( "No models available" );
        }
        else
        {
            ImGui::SetNextItemWidth( ImGui::GetContentRegionAvail().x );
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
        if( responding ) ImGui::EndDisabled();

        ImGui::Checkbox( ICON_FA_EARTH_AMERICAS " Internet access", &m_tools->m_netAccess );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( ImGui::Checkbox( ICON_FA_TAG " Annotate call stacks", &s_config.llmAnnotateCallstacks ) )
        {
            SaveConfig();
        }

        if( ImGui::TreeNode( "Advanced" ) )
        {
            if( responding ) ImGui::BeginDisabled();
            ImGui::Checkbox( ICON_FA_TEMPERATURE_HALF " Temperature", &m_setTemperature );
            ImGui::SameLine();
            ImGui::SetNextItemWidth( 40 * scale );
            if( ImGui::InputFloat( "##temperature", &m_temperature, 0, 0, "%.2f" ) ) m_temperature = std::clamp( m_temperature, 0.f, 2.f );
            if( responding ) ImGui::EndDisabled();

            ImGui::Checkbox( ICON_FA_LIGHTBULB " Show all thinking regions", &m_allThinkingRegions );

            char buf[1024];

            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted( "User agent:" );
            ImGui::SameLine();
            snprintf( buf, sizeof( buf ), "%s", s_config.llmUserAgent.c_str() );
            ImGui::SetNextItemWidth( ImGui::GetContentRegionAvail().x );
            if( ImGui::InputTextWithHint( "##useragent", "Spoof user agent", buf, sizeof( buf ) ) )
            {
                s_config.llmUserAgent = buf;
                SaveConfig();
            }

            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted( "Google Search Engine:" );
            ImGui::SameLine();
            snprintf( buf, sizeof( buf ), "%s", s_config.llmSearchIdentifier.c_str() );
            ImGui::SetNextItemWidth( ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize( ICON_FA_HOUSE ).x - ImGui::GetStyle().FramePadding.x * 2 - ImGui::GetStyle().ItemSpacing.x );
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
            ImGui::SetNextItemWidth( ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize( ICON_FA_HOUSE ).x - ImGui::GetStyle().FramePadding.x * 2 - ImGui::GetStyle().ItemSpacing.x );
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
            m_jobsLock.lock();
            if( m_currentJob ) m_currentJob->stop = true;
            m_jobsLock.unlock();
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

        int thinkIdx = 0;
        if( !m_allThinkingRegions )
        {
            for( thinkIdx = m_chat.size(); thinkIdx > 0; thinkIdx-- )
            {
                const auto& line = m_chat[thinkIdx-1];
                if( !line.contains( "role" ) ) break;
                const auto& roleStr = line["role"].get_ref<const std::string&>();
                if( roleStr == "tool" ) continue;
                if( roleStr == "assistant" && !line.contains( "content" ) ) continue;
                break;
            }
        }

        int turnIdx = 0;
        for( auto it = m_chat.begin(); it != m_chat.end(); ++it )
        {
            const auto& line = *it;
            if( !line.contains( "role" ) ) break;
            const auto& roleStr = line["role"].get_ref<const std::string&>();
            if( roleStr == "system" ) continue;

            TracyLlmChat::TurnRole role = TracyLlmChat::TurnRole::None;
            if( roleStr == "user" ) role = TracyLlmChat::TurnRole::User;
            else if( roleStr == "error" ) role = TracyLlmChat::TurnRole::Error;
            else if( roleStr == "assistant" || roleStr == "tool" ) role = TracyLlmChat::TurnRole::Assistant;
            else assert( false );

            if( role == TracyLlmChat::TurnRole::User )
            {
                if( line.contains( "content" ) && line["content"].get_ref<const std::string&>().starts_with( "<attachment>\n" ) ) role = TracyLlmChat::TurnRole::Attachment;
            }

            ImGui::PushID( turnIdx++ );
            TracyLlmChat::Think think = TracyLlmChat::Think::Hide;
            if( thinkIdx <= turnIdx )
            {
                think = TracyLlmChat::Think::Show;
            }
            else if( thinkIdx == turnIdx + 1 && role == TracyLlmChat::TurnRole::Assistant && line.contains( "content" ) )
            {
                think = TracyLlmChat::Think::ToolCall;
            }
            if( !m_chatUi->Turn( role, it, m_chat.end(), think, turnIdx == m_chat.size() - 1 ) )
            {
                if( role == TracyLlmChat::TurnRole::Assistant )
                {
                    std::lock_guard lock( m_jobsLock );
                    if( m_currentJob ) m_currentJob->stop = true;
                    QueueSendMessage();
                }
                else if( role == TracyLlmChat::TurnRole::User )
                {
                    if( line.contains( "content" ) )
                    {
                        auto& content = line["content"].get_ref<const std::string&>();
                        const auto sz = std::min( InputBufferSize - 1, content.size() );
                        memcpy( m_input, content.data(), sz );
                        m_input[sz] = 0;
                        inputChanged = true;
                    }
                }

                auto cit = it;
                while( cit != m_chat.end() )
                {
                    auto& v = *cit;
                    int tokens = 0;
                    int length = 0;
                    if( v.contains( "content" ) )
                    {
                        auto& str = v["content"].get_ref<std::string&>();
                        tokens = m_api->Tokenize( str, m_modelIdx );
                        length = str.size();
                    }
                    if( v.contains( "reasoning_content" ) )
                    {
                        auto& str = v["reasoning_content"].get_ref<std::string&>();
                        tokens += m_api->Tokenize( str, m_modelIdx );
                        length += str.size();
                    }
                    m_usedCtx -= tokens >= 0 ? tokens : length / 4;
                    ++cit;
                }

                m_chat.erase( it, m_chat.end() );
                if( role == TracyLlmChat::TurnRole::User )
                {
                    m_jobsLock.lock();
                    if( m_currentJob ) m_currentJob->stop = true;
                    m_jobsLock.unlock();
                }
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

    m_jobsLock.lock();
    if( m_currentJob )
    {
        const bool disabled = m_currentJob->stop;
        if( disabled ) ImGui::BeginDisabled();
        if( ImGui::Button( ICON_FA_STOP " Stop" ) ) m_currentJob->stop = true;
        m_jobsLock.unlock();
        if( disabled ) ImGui::EndDisabled();
        ImGui::SameLine();
        DrawWaitingDots( s_time );
        ImGui::SameLine();
        if( disabled )
        {
            ImGui::TextUnformatted( "Stopping…" );
        }
        else
        {
            ImGui::TextUnformatted( "Generating…" );
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
        m_jobsLock.unlock();
        const char* buttonText = ICON_FA_PAPER_PLANE;
        auto buttonSize = ImGui::CalcTextSize( buttonText );
        buttonSize.x += ImGui::GetStyle().FramePadding.x * 2.0f + ImGui::GetStyle().ItemSpacing.x;
        ImGui::PushItemWidth( ImGui::GetContentRegionAvail().x - buttonSize.x );
        if( inputChanged ) ImGui::GetInputTextState( ImGui::GetCurrentWindow()->GetID( "##chat_input" ) )->ReloadUserBufAndMoveToEnd();
        bool send = ImGui::InputTextWithHint( "##chat_input", "Write your question here…", m_input, InputBufferSize, ImGuiInputTextFlags_EnterReturnsTrue );
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
                std::lock_guard lock( m_jobsLock );
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
    std::unique_lock lock( m_jobsLock );
    while( !m_exit.load( std::memory_order_acquire ) )
    {
        m_cv.wait( lock, [this] { return !m_jobs.empty() || m_exit.load( std::memory_order_acquire ); } );
        if( m_exit.load( std::memory_order_acquire ) ) break;

        m_currentJob = std::move( m_jobs.front() );
        m_jobs.erase( m_jobs.begin() );

        switch( m_currentJob->task )
        {
        case Task::Connect:
        {
            auto callback = m_currentJob->callback;
            m_busy = true;
            lock.unlock();
            m_api->Connect( s_config.llmAddress.c_str() );
            callback();
            lock.lock();
            m_busy = false;
            break;
        }
        case Task::SendMessage:
            lock.unlock();
            SendMessage();
            lock.lock();
            break;
        case Task::FastMessage:
        {
            auto param = m_currentJob->param2;
            auto callback = m_currentJob->callback2;
            lock.unlock();
            auto response = m_api->SendMessage( param, m_fastIdx );
            callback( response );
            lock.lock();
            break;
        }
        case Task::Tokenize:
        {
            auto param = m_currentJob->param;
            auto callback = m_currentJob->callback2;
            lock.unlock();
            auto tokens = m_api->Tokenize( param, m_modelIdx );
            if( tokens < 0 ) tokens = param.size() / 4;
            callback( { { "tokens", tokens } } );
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
    m_fastIdx = -1;
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

    it = std::ranges::find_if( models, []( const auto& model ) { return model.name == s_config.llmFastModel; } );
    if( it == models.end() )
    {
        for( int i=0; i<models.size(); i++ )
        {
            if( !models[i].embeddings )
            {
                m_fastIdx = i;
                break;
            }
        }
    }
    else
    {
        m_fastIdx = std::distance( models.begin(), it );
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

static void Replace( std::string& str, std::string_view from, std::string_view to )
{
    std::string::size_type pos;
    while( ( pos = str.find( from ) ) != std::string::npos )
    {
        str.replace( pos, from.size(), to );
    }
}

void TracyLlm::ResetChat()
{
    *m_input = 0;
    m_usedCtx = 0;
    m_chatId++;
    m_chat.clear();

    UpdateSystemPrompt();
}

void TracyLlm::UpdateSystemPrompt()
{
    static constexpr std::string_view UserToken = "%USER%";
    static constexpr std::string_view TimeToken = "%TIME%";
    static constexpr std::string_view ProgramNameToken = "%PROGRAMNAME%";

    auto userName = GetUserFullName();
    if( !userName ) userName = GetUserLogin();

    auto systemPrompt = std::string( m_systemPrompt->data(), m_systemPrompt->size() );

    Replace( systemPrompt, UserToken, userName );
    Replace( systemPrompt, TimeToken, m_tools->GetCurrentTime() );
    Replace( systemPrompt, ProgramNameToken, m_worker.GetCaptureProgram() );

    if( !m_api )
    {
        m_chat.push_back( {
            { "role", "system" },
            { "content", systemPrompt }
        } );
    }
    else if( m_chat.empty() )
    {
        std::lock_guard lock( m_jobsLock );
        AddMessage( std::move( systemPrompt ), "system" );
    }
    else
    {
        m_chat[0]["content"] = systemPrompt;
    }
}

// requires m_jobsLock
void TracyLlm::QueueConnect()
{
    m_jobs.emplace_back( std::make_shared<WorkItem>( WorkItem {
        .task = Task::Connect,
        .callback = [this] { UpdateModels(); }
    } ) );
    m_cv.notify_all();
}

bool TracyLlm::QueueSendMessageLocking()
{
    std::unique_lock<std::mutex> lock( m_jobsLock );
    return QueueSendMessage();
}

// requires m_jobsLock
bool TracyLlm::QueueSendMessage()
{
    if( !m_api->IsConnected() || m_modelIdx < 0 ) return false;
    m_jobs.emplace_back( std::make_shared<WorkItem>( WorkItem {
        .task = Task::SendMessage
    } ) );
    m_cv.notify_all();
    return true;
}

bool TracyLlm::QueueFastMessageLocking( const nlohmann::json& req, std::function<void(nlohmann::json)> callback )
{
    std::unique_lock<std::mutex> lock( m_jobsLock );
    return QueueFastMessage( req, std::move( callback ) );
}

// requires m_jobsLock
bool TracyLlm::QueueFastMessage( const nlohmann::json& req, std::function<void(nlohmann::json)> callback )
{
    if( !m_api->IsConnected() || m_fastIdx < 0 ) return false;
    m_jobs.emplace_back( std::make_shared<WorkItem>( WorkItem {
        .task = Task::FastMessage,
        .callback2 = std::move( callback ),
        .param2 = req
    } ) );
    m_cv.notify_all();
    return true;
}

void TracyLlm::AddMessageLocking( std::string&& str, const char* role )
{
    std::unique_lock<std::mutex> lock( m_jobsLock );
    AddMessage( std::move( str ), role );
}

// requires m_jobsLock
void TracyLlm::AddMessage( std::string&& str, const char* role )
{
    assert( m_api );
    m_jobs.emplace_back( std::make_shared<WorkItem>( WorkItem {
        .task = Task::Tokenize,
        .callback2 = [this, str, role]( nlohmann::json json ) {
            std::lock_guard lock( m_chatLock );
            m_usedCtx += json["tokens"].get<int>();
            if( m_chat.size() == 1 ) UpdateSystemPrompt();
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

void TracyLlm::AddMessageBlocking( std::string&& str, const char* role )
{
    assert( m_api );
    const auto tokens = m_api->Tokenize( str, m_modelIdx );
    m_usedCtx += tokens >= 0 ? tokens : str.size() / 4;

    nlohmann::json msg;
    msg["role"] = role;
    msg["content"] = std::move( str );

    std::lock_guard lock( m_chatLock );
    m_chat.emplace_back( std::move( msg ) );
}

void TracyLlm::AddMessageBlocking( nlohmann::json&& json )
{
    auto dump = json.dump();
    assert( m_api );
    const auto tokens = m_api->Tokenize( dump, m_modelIdx );
    m_usedCtx += tokens >= 0 ? tokens : dump.size() / 4;

    std::lock_guard lock( m_chatLock );
    m_chat.emplace_back( std::move( json ) );
}

void TracyLlm::AddAttachmentLocking( std::string&& str, const char* role )
{
    std::unique_lock<std::mutex> lock( m_jobsLock );
    AddMessage( "<attachment>\n" + std::move( str ), role );
}

void TracyLlm::ManageContext()
{
    const auto& models = m_api->GetModels();
    const auto ctxSize = models[m_modelIdx].contextSize;
    if( ctxSize <= 0 ) return;

    const auto quota = std::max( 4096, int( ctxSize * 0.8f ) );
    if( m_usedCtx < quota ) return;

    size_t idx = 0;
    std::vector<std::pair<size_t, size_t>> toolOutputs;
    for( auto& msg : m_chat )
    {
        if( msg["role"].get_ref<const std::string&>() == "tool" )
        {
            auto& str = msg["content"].get_ref<const std::string&>();
            toolOutputs.emplace_back( str.size(), idx );
        }
        idx++;
    }
    if( toolOutputs.size() > 1 )
    {
        // keep the last tool output
        toolOutputs.pop_back();

        // exponentially increase sizes of old tool outputs to prefer the most recent
        constexpr float K = 1.1f;
        for( size_t i=0; i<toolOutputs.size(); i++ ) toolOutputs[i].first *= std::pow( K, toolOutputs.size() - i );

        // remove the largest tool output
        std::ranges::stable_sort( toolOutputs, []( const auto& a, const auto& b ) { return a.first > b.first; } );
        for( auto& v : toolOutputs )
        {
            auto tokens = m_api->Tokenize( m_chat[v.second]["content"].get_ref<const std::string&>(), m_modelIdx );
            m_usedCtx -= tokens >= 0 ? tokens : v.first / 4;

            m_chat[v.second]["content"] = TracyLlmChat::ForgetMsg;
            tokens = m_api->Tokenize( TracyLlmChat::ForgetMsg, m_modelIdx );
            m_usedCtx += tokens >= 0 ? tokens : strlen( TracyLlmChat::ForgetMsg ) / 4;

            if( m_usedCtx < quota ) break;
        }
    }
}

void TracyLlm::SendMessage()
{
    std::unique_lock lock( m_chatLock );
    ManageContext();
    auto chat = m_chat;
    lock.unlock();

    try
    {
        AddMessageBlocking( { { "role", "assistant" } } );

        size_t i = 1;
        while( i < chat.size() )
        {
            if( chat[i]["role"].get_ref<const std::string&>() == "user" &&
                chat[i-1]["role"].get_ref<const std::string&>() == "user" )
            {
                auto& str = chat[i-1]["content"].get_ref<std::string&>();
                assert( str.starts_with( "<attachment>\n" ) );
                str.append( "</attachment>\n\n" );
                str.append( chat[i]["content"].get_ref<const std::string&>() );
                chat.erase( chat.begin() + i );
            }
            else
            {
                i++;
            }
        }

        nlohmann::json req;
        req["model"] = m_api->GetModels()[m_modelIdx].name;
        req["messages"] = std::move( chat );
        req["stream"] = true;
        req["cache_prompt"] = true;
        req["tools"] = m_toolsJson;
        if( m_setTemperature ) req["temperature"] = m_temperature;

        m_api->ChatCompletion( req, [this]( const nlohmann::json& response ) -> bool { return OnResponse( response ); }, m_modelIdx );
    }
    catch( std::exception& e )
    {
        lock.lock();
        if( !m_chat.empty() && m_chat.back()["role"].get_ref<const std::string&>() == "assistant" ) m_chat.pop_back();
        lock.unlock();
        AddMessageBlocking( e.what(), "error" );
    }
}

void TracyLlm::AppendResponse( const char* name, const nlohmann::json& delta )
{
    if( delta.contains( name ) )
    {
        auto& json = delta[name];
        if( json.is_string() )
        {
            std::string str = json.get_ref<const std::string&>();
            std::erase( str, '\r' );

            auto& back = m_chat.back();
            if( back.contains( name ) )
            {
                assert( back[name].is_string() );
                back[name].get_ref<std::string&>().append( str );
            }
            else
            {
                back[name] = std::move( str );
            }

            m_usedCtx++;
        }
        else if( json.is_array() )
        {
            assert( json.size() == 1 );
            auto& val = json[0];
            auto index = val["index"].get<size_t>();

            auto& back = m_chat.back();
            if( !back.contains( name ) ) back[name] = nlohmann::json::array();

            auto& arr = back[name].get_ref<nlohmann::json::array_t&>();
            if( index == arr.size() )
            {
                arr.push_back( val );
            }
            else
            {
                arr[index]["function"]["arguments"].get_ref<std::string&>().append( val["function"]["arguments"].get_ref<const std::string&>() );
            }
        }
    }
}

bool TracyLlm::OnResponse( const nlohmann::json& json )
{
    std::unique_lock chatLock( m_chatLock );
    std::unique_lock jobsLock( m_jobsLock );
    if( m_currentJob->stop )
    {
        m_focusInput = true;
        return false;
    }
    jobsLock.unlock();

    assert( m_chat.back()["role"].get_ref<const std::string&>() == "assistant" );

    bool done = false;
    try
    {
        if( json.contains( "choices" ) )
        {
            auto& choices = json["choices"];
            if( !choices.empty() )
            {
                auto& node = choices[0];
                auto& delta = node["delta"];

                AppendResponse( "content", delta );
                AppendResponse( "reasoning_content", delta );
                AppendResponse( "tool_calls", delta );

                done = node.contains( "finish_reason" ) && !node["finish_reason"].empty();
            }
        }
        else if( json.contains( "error" ) )
        {
            jobsLock.lock();
            AddMessage( json["error"].dump( 2 ), "error" );
            m_focusInput = true;
            return false;
        }
    }
    catch( const nlohmann::json::exception& e )
    {
        m_jobsLock.lock();
        m_focusInput = true;
        return false;
    }

    if( done )
    {
        if( json.contains( "usage" ) )
        {
            auto& usage = json["usage"];
            if( usage.contains( "total_tokens" ) ) m_usedCtx = usage["total_tokens"].get<int>();
        }

        auto& back = m_chat.back();
        if( back.contains( "tool_calls" ) )
        {
            auto calls = back["tool_calls"];
            chatLock.unlock();
            for( auto& call : calls )
            {
                auto& id = call["id"].get_ref<const std::string&>();
                auto& function = call["function"];
                auto& name = function["name"].get_ref<const std::string&>();
                auto& arguments = function["arguments"].get_ref<const std::string&>();

                std::string result;
                try
                {
                    result = m_tools->HandleToolCalls( name, nlohmann::json::parse( arguments ), *m_api, m_api->GetModels()[m_modelIdx].contextSize, m_embedIdx >= 0 );
                }
                catch( const nlohmann::json::exception& e )
                {
                    result = nlohmann::json { "error", e.what() };
                }

                nlohmann::json reply = {
                    { "role", "tool" },
                    { "tool_call_id", id },
                    { "name", name },
                    { "content", result }
                };
                AddMessageBlocking( std::move( reply ) );
            }
            jobsLock.lock();
            QueueSendMessage();
        }
        else
        {
            jobsLock.lock();
            m_focusInput = true;
        }
    }

    return true;
}

}
