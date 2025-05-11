#include <ollama.hpp>

#include "TracyLlm.hpp"

namespace tracy
{

TracyLlm::TracyLlm()
{
    m_ollama = std::make_unique<Ollama>();
}

}
