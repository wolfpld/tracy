#include <ranges>
#include <ollama.hpp>

#include "TracyConfig.hpp"
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

    const auto models = m_ollama->list_models();
    if( models.empty() )
    {
        m_ollama.reset();
        return;
    }

    m_model = s_config.llmModel;
    if( std::ranges::find( models, m_model ) == models.end() ) m_model = models[0];

    m_ctxSize = GetCtxSize( m_model );
    if( m_ctxSize == 0 )
    {
        m_ollama.reset();
        return;
    }
}

TracyLlm::~TracyLlm()
{
}

std::string TracyLlm::GetVersion() const
{
    return m_ollama->get_version();
}

std::vector<std::string> TracyLlm::GetModels() const
{
    return m_ollama->list_models();
}

size_t TracyLlm::GetCtxSize( const std::string& model ) const
{
    try
    {
        const auto info = m_ollama->show_model_info( model );
        const auto& modelInfo = info["model_info"];
        const auto architecture = modelInfo["general.architecture"].get<std::string>();
        const auto& ctx = modelInfo[architecture + ".context_length"];
        return ctx.get<size_t>();
    }
    catch( const std::exception& e )
    {
        return 0;
    }
}

}
