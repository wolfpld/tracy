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
    struct LlmModel
    {
        std::string name;
        size_t ctxSize;
    };

    TracyLlm();
    ~TracyLlm();

    [[nodiscard]] bool IsValid() const { return (bool)m_ollama; }
    [[nodiscard]] std::string GetVersion() const;
    [[nodiscard]] std::vector<LlmModel> GetModels() const { return m_models; }

    void Draw();

    bool m_show = false;

private:
    void LoadModels();

    std::unique_ptr<Ollama> m_ollama;
    std::vector<LlmModel> m_models;

    size_t m_modelIdx;
    size_t m_ctxSize;
};

}

#endif
