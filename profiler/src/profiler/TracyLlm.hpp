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
    ~TracyLlm();

    [[nodiscard]] bool IsValid() const { return m_valid; }
    [[nodiscard]] std::string GetVersion() const;

private:
    std::unique_ptr<Ollama> m_ollama;
    bool m_valid;
};

}

#endif
