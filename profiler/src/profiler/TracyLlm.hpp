#ifndef __TRACYLLM_HPP__
#define __TRACYLLM_HPP__

#include <memory>

class Ollama;

namespace tracy
{

class TracyLlm
{
public:
    TracyLlm();

private:
    std::unique_ptr<Ollama> m_ollama;
};

}

#endif
