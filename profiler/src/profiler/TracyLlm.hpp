#ifndef __TRACYLLM_HPP__
#define __TRACYLLM_HPP__

#include <memory>
#include <string>
#include <vector>

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
    [[nodiscard]] std::vector<std::string> GetModels() const;

private:
    std::unique_ptr<Ollama> m_ollama;
    bool m_valid;
};

}

#endif
