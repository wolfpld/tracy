#include <curl/curl.h>
#include <stdint.h>
#include <stdlib.h>
#include <ranges>

#include "TracyConfig.hpp"
#include "TracyImGui.hpp"
#include "TracyLlm.hpp"
#include "TracyLlmApi.hpp"
#include "TracyPrint.hpp"
#include "TracyWeb.hpp"
#include "../Fonts.hpp"

#include "data/SystemPrompt.hpp"
#include "data/SystemReminder.hpp"

namespace tracy
{

extern double s_time;

constexpr const char* ForgetMsg = "<tool_output>\n...";
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

    m_systemPrompt = Unembed( SystemPrompt );
    m_systemReminder = Unembed( SystemReminder );

    m_input = new char[InputBufferSize];
    m_apiInput = new char[InputBufferSize];
    ResetChat();

    m_api = std::make_unique<TracyLlmApi>();

    m_busy = true;
    m_jobs.emplace_back( WorkItem {
        .task = Task::Connect,
        .callback = [this] { UpdateModels(); }
    } );
    m_thread = std::thread( [this] { Worker(); } );
}

TracyLlm::~TracyLlm()
{
    delete[] m_input;
    delete[] m_apiInput;

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

void TracyLlm::Draw()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 400 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Tracy Assist", &m_show, ImGuiWindowFlags_NoScrollbar );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

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

    const auto manualEmbeddingsState = m_tools.GetManualEmbeddingsState();
    if( manualEmbeddingsState.inProgress )
    {
        ImGui::PushFont( g_fonts.big );
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
        if( ImGui::Button( "Cancel" ) ) m_tools.CancelManualEmbeddings();
        ImGui::End();
        return;
    }

    std::lock_guard lock( m_lock );

    const auto hasChat = m_chat.size() <= 1 && *m_input == 0;
    if( hasChat ) ImGui::BeginDisabled();
    if( ImGui::Button( ICON_FA_BROOM " Clear chat" ) )
    {
        if( m_responding ) m_stop = true;
        ResetChat();
    }
    if( hasChat ) ImGui::EndDisabled();
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_ARROWS_ROTATE " Reconnect" ) )
    {
        if( m_responding ) m_stop = true;
        m_jobs.emplace_back( WorkItem {
            .task = Task::Connect,
            .callback = [this] { UpdateModels(); }
        } );
        m_cv.notify_all();
    }

    ImGui::SameLine();
    if( ImGui::TreeNode( "Settings" ) )
    {
        ImGui::Spacing();
        ImGui::AlignTextToFramePadding();
        TextDisabledUnformatted( "API:" );
        ImGui::SameLine();
        const auto sz = std::min( InputBufferSize-1, s_config.llmAddress.size() );
        memcpy( m_apiInput, s_config.llmAddress.c_str(), sz );
        m_apiInput[sz] = 0;
        bool changed = ImGui::InputTextWithHint( "##api", "http://127.0.0.1:1234", m_apiInput, InputBufferSize );
        ImGui::SameLine();
        if( ImGui::BeginCombo( "##presets", nullptr, ImGuiComboFlags_NoPreview ) )
        {
            struct Preset
            {
                const char* name;
                const char* address;
            };
            constexpr static std::array presets = {
                Preset { "Ollama", "http://localhost:11434" },
                Preset { "LM Studio", "http://localhost:1234" },
                Preset { "Jan / Cortex", "http://localhost:1337" },
                Preset { "Llama.cpp", "http://localhost:8080" },
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
            m_jobs.emplace_back( WorkItem {
                .task = Task::Connect,
                .callback = [this] { UpdateModels(); }
            } );
            m_cv.notify_all();
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
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", model.quant.c_str() );
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
                    }
                    if( m_embedIdx == i ) ImGui::SetItemDefaultFocus();
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", model.quant.c_str() );
                }
                ImGui::EndCombo();
            }
        }

        ImGui::Checkbox( ICON_FA_TEMPERATURE_HALF " Temperature", &m_setTemperature );
        ImGui::SameLine();
        ImGui::SetNextItemWidth( 40 * scale );
        if( ImGui::InputFloat( "##temperature", &m_temperature, 0, 0, "%.2f" ) ) m_temperature = std::clamp( m_temperature, 0.f, 2.f );

        ImGui::Checkbox( ICON_FA_GLOBE " Internet access", &m_tools.m_netAccess );

        if( ImGui::TreeNode( "External services" ) )
        {
            char buf[1024];

            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted( "Readability.js:" );
            ImGui::SameLine();
            snprintf( buf, sizeof( buf ), "%s", s_config.llmReadability.c_str() );
            if( ImGui::InputTextWithHint( "##readability", "http://127.0.0.1:3000", buf, sizeof( buf ) ) )
            {
                s_config.llmReadability = buf;
                SaveConfig();
            }
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_HOUSE ) ) OpenWebpage( "https://github.com/phpdocker-io/readability-js-server" );

            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted( "User agent:" );
            ImGui::SameLine();
            snprintf( buf, sizeof( buf ), "%s", s_config.llmUserAgent.c_str() );
            if( ImGui::InputTextWithHint( "##useragent", "Spoof user agent", buf, sizeof( buf ) ) )
            {
                s_config.llmUserAgent = buf;
                SaveConfig();
            }

            ImGui::TreePop();
        }

        ImGui::TreePop();
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

    if( !m_api->IsConnected() )
    {
        ImGui::PushFont( g_fonts.big );
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
        ImGui::PushFont( g_fonts.big );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
        TextCentered( ICON_FA_WORM );
        ImGui::Spacing();
        TextCentered( "No models available." );
        ImGui::PopFont();
        ImGui::End();
        return;
    }

    if( !manualEmbeddingsState.done || manualEmbeddingsState.model != models[m_embedIdx].name )
    {
        if( m_embedIdx < 0 ) ImGui::BeginDisabled();
        if( ImGui::SmallButton( ICON_FA_BOOK_BOOKMARK " Learn manual" ) )
        {
            if( m_responding ) m_stop = true;
            m_tools.BuildManualEmbeddings( models[m_embedIdx].name, *m_api );
        }
        if( m_embedIdx < 0 ) ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::PushFont( g_fonts.small );
        ImGui::AlignTextToFramePadding();
        if( !manualEmbeddingsState.done )
        {
            tracy::TextDisabledUnformatted( "Embeddings not calculated" );
        }
        else
        {
            ImGui::TextDisabled( "Embeddings calculated for model %s", manualEmbeddingsState.model.c_str() );
        }
        ImGui::PopFont();
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

    ImGui::Spacing();
    ImGui::BeginChild( "##chat", ImVec2( 0, -( ImGui::GetFrameHeight() + style.ItemSpacing.y * 2 ) ), ImGuiChildFlags_Borders, ImGuiWindowFlags_AlwaysVerticalScrollbar );
    if( m_chat.size() <= 1 )   // account for system prompt
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
        for( auto& line : m_chat )
        {
            const auto uw = ImGui::CalcTextSize( ICON_FA_USER ).x;
            const auto rw = ImGui::CalcTextSize( ICON_FA_ROBOT ).x;
            const auto ew = ImGui::CalcTextSize( ICON_FA_CIRCLE_EXCLAMATION ).x;
            const auto yw = ImGui::CalcTextSize( ICON_FA_REPLY ).x;
            const auto cw = ImGui::CalcTextSize( ICON_FA_RECYCLE ).x;
            const auto mw = std::max( { uw, rw, ew, yw, cw } );

            const auto posStart = ImGui::GetCursorPos().x;
            const auto& role = line["role"].get_ref<const std::string&>();

            if( role == "system" ) continue;

            const auto isUser = role == "user";
            const auto isError = role == "error";
            const auto isAssistant = role == "assistant";
            const auto isToolResponse = isUser && line["content"].get_ref<const std::string&>().starts_with( "<tool_output>\n" );
            const auto isForgotten = isToolResponse && line["content"].is_string() && line["content"].get_ref<const std::string&>() == ForgetMsg;

            float diff, offset;
            if( isForgotten )
            {
                diff = mw - cw;
                offset = diff / 2;
                ImGui::Dummy( ImVec2( offset, 0 ) );
                ImGui::SameLine( 0, 0 );
                ImGui::TextColored( style.Colors[ImGuiCol_TextDisabled], ICON_FA_RECYCLE );
            }
            else if( isToolResponse )
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

            if( isForgotten )
            {
                ImGui::TextUnformatted( "Tool response removed to save context space" );
                treeIdx++;
            }
            else if( isToolResponse )
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
            else if( line["content"].is_string() )
            {
                auto& string = line["content"].get_ref<const std::string&>();
                PrintMarkdown( string.c_str() );
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
        bool send = ImGui::InputTextWithHint( "##chat_input", "Write your question here...", m_input, InputBufferSize, ImGuiInputTextFlags_EnterReturnsTrue );
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
                AddMessage( ptr, "user" );

                *m_input = 0;
                m_responding = true;

                m_jobs.emplace_back( WorkItem {
                    .task = Task::SendMessage,
                    .callback = nullptr
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
        case Task::Connect:
            m_busy = true;
            lock.unlock();
            m_api->Connect( s_config.llmAddress.c_str() );
            job.callback();
            lock.lock();
            m_busy = false;
            break;
        case Task::SendMessage:
            SendMessage( lock );
            break;
        default:
            assert( false );
            break;
        }
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
}

void TracyLlm::ResetChat()
{
    std::string systemPrompt = "<SYSTEM_PROMPT>\n";
    systemPrompt += std::string( m_systemPrompt->data(), m_systemPrompt->size() );
    systemPrompt += "The current time is: " + m_tools.GetCurrentTime() + "\n";
    systemPrompt += "</SYSTEM_PROMPT>\n";

    *m_input = 0;
    m_usedCtx = 0;
    m_chatId++;
    m_chat.clear();
    m_chatCache.clear();

    AddMessage( std::move( systemPrompt ), "system" );
}

void TracyLlm::AddMessage( std::string&& str, const char* role )
{
    m_usedCtx += str.size() / 4;

    nlohmann::json msg;
    msg["role"] = role;
    msg["content"] = std::move( str );

    m_chat.emplace_back( std::move( msg ) );
}

void TracyLlm::SendMessage( std::unique_lock<std::mutex>& lock )
{
    const auto& models = m_api->GetModels();
    const auto ctxSize = models[m_modelIdx].contextSize;
    if( ctxSize > 0 && (float)m_usedCtx / ctxSize > 0.7f )
    {
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
            auto& v = toolOutputs[0];
            m_usedCtx -= v.first / 4;
            m_chat[v.second]["content"] = ForgetMsg;
            m_usedCtx += strlen( ForgetMsg ) / 4;
        }
    }

    AddMessage( "<think>\n", "assistant" );

    bool res;
    try
    {
        auto chat = m_chat;
        lock.unlock();

        std::string inject;
        inject += "<SYSTEM_REMINDER>\n";
        inject += std::string( m_systemReminder->data(), m_systemReminder->size() );
        inject += "The current time is: " + m_tools.GetCurrentTime() + "\n";
        inject += "</SYSTEM_REMINDER>\n";

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
        AddMessage( e.what(), "error" );
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

bool TracyLlm::OnResponse( const nlohmann::json& json )
{
    std::unique_lock lock( m_lock );

    if( m_stop )
    {
        m_stop = false;
        m_responding = false;
        m_focusInput = true;
        return false;
    }

    auto& back = m_chat.back();
    auto& content = back["content"];
    const auto& str = content.get_ref<const std::string&>();

    std::string responseStr;
    bool done;
    try
    {
        auto& node = json["choices"][0];
        auto& delta = node["delta"];
        if( delta.contains( "content" ) && delta["content"].is_string() ) responseStr = delta["content"].get_ref<const std::string&>();
        done = !node["finish_reason"].empty();
    }
    catch( const nlohmann::json::exception& e )
    {
        if( m_responding )
        {
            m_responding = false;
            m_focusInput = true;
        }
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
                    const auto reply = m_tools.HandleToolCalls( tool, lines, *m_api, m_api->GetModels()[m_modelIdx].contextSize, m_embedIdx >= 0 );
                    auto output = "<tool_output>\n" + reply.reply;
                    lock.lock();
                    //if( reply.image.empty() )
                    {
                        AddMessage( std::move( output ), "user" );
                    }
                    /*
                    else
                    {
                        std::vector<ollama::image> images;
                        images.emplace_back( ollama::image::from_base64_string( reply.image ) );
                        m_chat->emplace_back( ollama::message( "user", output, images ) );
                    }
                    */

                    m_jobs.emplace_back( WorkItem {
                        .task = Task::SendMessage,
                        .callback = nullptr
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
            snprintf( tmp, sizeof( tmp ), "##chat_code_%d", num );
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
