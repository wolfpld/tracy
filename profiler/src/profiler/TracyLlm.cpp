#include <ranges>
#include <ollama.hpp>

#include "TracyConfig.hpp"
#include "TracyImGui.hpp"
#include "TracyLlm.hpp"

extern tracy::Config s_config;

namespace tracy
{

TracyLlm::TracyLlm()
{
    if( !s_config.llm ) return;

    m_ollama = std::make_unique<Ollama>( s_config.llmAddress );
    if( !m_ollama->is_running() )
    {
        m_ollama.reset();
        return;
    }

    try
    {
        LoadModels();
    }
    catch( const std::exception& e )
    {
        m_ollama.reset();
        return;
    }

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

TracyLlm::~TracyLlm()
{
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
    ImGui::End();
}

void TracyLlm::LoadModels()
{
    m_models.clear();
    const auto models = m_ollama->list_models();
    for( const auto& model : models )
    {
        const auto info = m_ollama->show_model_info( model );
        const auto& modelInfo = info["model_info"];
        const auto architecture = modelInfo["general.architecture"].get<std::string>();
        const auto& ctx = modelInfo[architecture + ".context_length"];
        m_models.emplace_back( LlmModel { .name = model, .ctxSize = ctx.get<size_t>() } );
    }
}

}
