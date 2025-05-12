#include <ranges>
#include <ollama.hpp>

#include "TracyConfig.hpp"
#include "TracyImGui.hpp"
#include "TracyLlm.hpp"
#include "TracyPrint.hpp"

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

    m_chat = std::make_unique<ollama::messages>();

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

    std::lock_guard lock( m_lock );

    if( ImGui::Button( ICON_FA_BROOM " Clear chat" ) )
    {
        if( m_responding ) m_stop = true;
        m_chat = std::make_unique<ollama::messages>();
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
                ImGui::TextDisabled( "(ctx: %s)", tracy::RealToString( m_models[i].ctxSize ) );
            }
            ImGui::EndCombo();
        }

        ImGui::AlignTextToFramePadding();
        TextDisabledUnformatted( "Context size:" );
        ImGui::SameLine();
        ImGui::SetNextItemWidth( 80 * scale );
        if( ImGui::InputInt( "##contextSize", &m_ctxPercent ) ) { m_ctxPercent = std::clamp( m_ctxPercent, 1, 100 ); }
        ImGui::SameLine();
        ImGui::TextUnformatted( "%" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( m_models[m_modelIdx].ctxSize * m_ctxPercent / 100 ) );

        ImGui::TreePop();
    }

    ImGui::Spacing();
    ImGui::BeginChild( "##ollama", ImVec2( 0, -( ImGui::GetFrameHeight() + ImGui::GetStyle().ItemSpacing.y * 2 ) ), ImGuiChildFlags_Borders, ImGuiWindowFlags_AlwaysVerticalScrollbar );
    if( m_chat->empty() )
    {
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 10 ) * 0.5f ) );
        ImGui::PushStyleColor( ImGuiCol_Text, ImGui::GetStyle().Colors[ImGuiCol_TextDisabled] );
        ImGui::TextWrapped( "What I had not realized is that extremely short exposures to a relatively simple computer program could induce powerful delusional thinking in quite normal people." );
        ImGui::Dummy( ImVec2( 0, ImGui::GetTextLineHeight() * 0.5f ) );
        const auto tw = ImGui::CalcTextSize( "-- Joseph Weizenbaum, 1976" ).x;
        ImGui::SetCursorPosX( ( ImGui::GetWindowWidth() - tw - 30 * scale ) );
        ImGui::TextUnformatted( "-- Joseph Weizenbaum, 1976" );
        ImGui::PopStyleColor();
    }
    else
    {
        int id = 0;
        for( auto& line : *m_chat )
        {
            const auto uw = ImGui::CalcTextSize( ICON_FA_USER ).x;
            const auto rw = ImGui::CalcTextSize( ICON_FA_ROBOT ).x;
            const auto ew = ImGui::CalcTextSize( ICON_FA_CIRCLE_EXCLAMATION ).x;
            const auto mw = std::max( { uw, rw, ew } );

            const auto posStart = ImGui::GetCursorPos().x;
            const auto role = line["role"].get<std::string>();
            const auto isUser = role == "user";
            const auto isError = role == "error";

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
            else
            {
                diff = mw - rw;
                offset = diff / 2;
                ImGui::Dummy( ImVec2( offset, 0 ) );
                ImGui::SameLine( 0, 0 );
                ImGui::TextColored( ImVec4( 0.4f, 0.5f, 1.f, 1.f ), ICON_FA_ROBOT );
            }
            ImGui::SameLine( 0, 0 );
            ImGui::Dummy( ImVec2( diff - offset, 0 ) );
            ImGui::SameLine();

            const auto indent = ImGui::GetCursorPos().x - posStart;

            auto& style = ImGui::GetStyle();
            if( isUser )
            {
                ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.65f, 0.65f, 0.65f, 1.f ) );
            }
            else if( isError )
            {
                ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 0.25f, 0.25f, 1.f ) );
            }
            else
            {
                ImGui::PushStyleColor( ImGuiCol_Text, style.Colors[ImGuiCol_Text] );
            }

            if( !isUser && !isError )
            {
                auto str = line["content"].get<std::string>();
                if( strncmp( str.c_str(), "<think>", 7 ) == 0 )
                {
                    int strip = 7;
                    while( str[strip] == '\n' ) strip++;
                    str = str.substr( strip );
                    auto pos = str.find( "</think>\n" );
                    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.5f, 0.5f, 0.3f, 1.f ) );
                    ImGui::PushID( id++ );
                    if( ImGui::TreeNode( ICON_FA_LIGHTBULB " Internal thoughts..." ) )
                    {
                        ImGui::Indent( indent );
                        ImGui::TextWrapped( "%s", str.substr( 0, pos ).c_str() );
                        ImGui::Unindent( indent );
                        ImGui::TreePop();
                    }
                    ImGui::PopID();
                    ImGui::PopStyleColor();
                    if( pos != std::string::npos )
                    {
                        strip = pos + 9;
                        while( str[strip] == '\n' ) strip++;
                        ImGui::Indent( indent );
                        ImGui::TextWrapped( "%s", str.substr( strip ).c_str() );
                        ImGui::Unindent( indent );
                    }
                }
                else
                {
                    ImGui::TextWrapped( "%s", line["content"].get<std::string>().c_str() );
                }
            }
            else
            {
                ImGui::TextWrapped( "%s", line["content"].get<std::string>().c_str() );
            }
            ImGui::PopStyleColor();
        }

        if( m_wasUpdated )
        {
            ImGui::SetScrollHereY( 1.f );
            m_wasUpdated = false;
        }
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
        if( ImGui::IsWindowAppearing() ) ImGui::SetKeyboardFocusHere( 0 );
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
            SendMessage( std::move( *job.chat ) );
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
        const auto architecture = modelInfo["general.architecture"].get<std::string>();
        const auto& ctx = modelInfo[architecture + ".context_length"];
        m.emplace_back( LlmModel { .name = model, .ctxSize = ctx.get<size_t>() } );
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

void TracyLlm::SendMessage( ollama::messages&& messages )
{
    ollama::options options;
    options["num_ctx"] = m_models[m_modelIdx].ctxSize * m_ctxPercent / 100;

    // The chat() call will fire a callback right away, so the assistant message needs to be there already
    m_chat->emplace_back( ollama::message( "assistant", "" ) );

    m_lock.unlock();
    bool res;
    try
    {
        res = m_ollama->chat( m_models[m_modelIdx].name, messages, [this]( const ollama::response& response ) -> bool { return OnResponse( response ); }, options );
    }
    catch( std::exception& e )
    {
        m_lock.lock();
        if( !m_chat->empty() && m_chat->back()["role"].get<std::string>() == "assistant" ) m_chat->pop_back();
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

bool TracyLlm::OnResponse( const ollama::response& response )
{
    std::lock_guard lock( m_lock );

    if( m_stop )
    {
        m_stop = false;
        m_responding = false;
        return false;
    }

    auto& back = m_chat->back()["content"];
    const auto str = back.get<std::string>();
    back = str + response.as_simple_string();
    m_wasUpdated = true;

    auto& json = response.as_json();
    if( json["done"] )
    {
        m_responding = false;
        return false;
    }

    return true;
}

}
