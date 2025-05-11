#include <ollama.hpp>

#include "TracyConfig.hpp"
#include "TracyLlm.hpp"

extern tracy::Config s_config;

namespace tracy
{

TracyLlm::TracyLlm()
    : m_valid( false )
{
    if( !s_config.llm ) return;

    m_ollama = std::make_unique<Ollama>( s_config.llmAddress );
    m_valid = m_ollama->is_running();
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

}
