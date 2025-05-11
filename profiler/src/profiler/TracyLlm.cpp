#include <ranges>
#include <ollama.hpp>

#include "TracyConfig.hpp"
#include "TracyImGui.hpp"
#include "TracyLlm.hpp"

extern tracy::Config s_config;

namespace tracy
{

extern double s_time;

TracyLlm::TracyLlm()
    : m_exit( false )
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

    m_jobs.emplace_back( WorkItem {
        .task = Task::LoadModels,
        .callback = [this] {
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
    } );
    m_thread = std::thread( [this] { Worker(); } );
}

TracyLlm::~TracyLlm()
{
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

}
