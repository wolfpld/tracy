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

    if( ImGui::SmallButton( ICON_FA_ARROWS_ROTATE ) )
    {
        std::lock_guard lock( m_lock );
        m_jobs.emplace_back( WorkItem {
            .task = Task::LoadModels,
            .callback = [this] { UpdateModels(); }
        } );
        m_cv.notify_all();
    }
    ImGui::SameLine();
    ImGui::TextDisabled( "Model:" );
    ImGui::SameLine();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
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
    ImGui::PopStyleVar();

    ImGui::Spacing();
    ImGui::BeginChild( "##ollama", ImVec2( 0, -( ImGui::GetFrameHeight() + ImGui::GetStyle().ItemSpacing.y * 2 ) ), ImGuiChildFlags_Borders );
    ImGui::EndChild();
    ImGui::Spacing();

    ImGui::PushItemWidth( -1 );
    if( ImGui::InputTextWithHint( "##ollama_input", "Write your question here...", m_input, InputBufferSize, ImGuiInputTextFlags_EnterReturnsTrue ) )
    {
        *m_input = 0;
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

        auto job = m_jobs.back();
        m_jobs.pop_back();
        m_busy = true;
        lock.unlock();

        switch( job.task )
        {
        case Task::LoadModels:
            LoadModels();
            break;
        default:
            assert( false );
            break;
        }

        job.callback();

        lock.lock();
        m_busy = false;
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

}
