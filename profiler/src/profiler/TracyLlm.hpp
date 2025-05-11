#ifndef __TRACYLLM_HPP__
#define __TRACYLLM_HPP__

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <imgui.h>

class Ollama;

namespace ollama
{
class message;
class messages;
}

namespace tracy
{

class TracyLlm
{
    enum class Task
    {
        LoadModels
    };

    struct WorkItem
    {
        Task task;
        std::function<void()> callback;
    };

public:
    struct LlmModel
    {
        std::string name;
        size_t ctxSize;
    };

    TracyLlm();
    ~TracyLlm();

    void UpdateFont( ImFont* fixed, ImFont* small, ImFont* big ) { m_font = fixed; m_smallFont = small; m_bigFont = big; }

    [[nodiscard]] bool IsValid() const { return (bool)m_ollama; }
    [[nodiscard]] bool IsBusy() const { std::lock_guard lock( m_lock); return m_busy; }

    [[nodiscard]] std::string GetVersion() const;
    [[nodiscard]] std::vector<LlmModel> GetModels() const { std::lock_guard lock( m_modelsLock ); return m_models; }

    void Draw();

    bool m_show = false;

private:
    void Worker();

    void LoadModels();
    void UpdateModels();

    std::unique_ptr<Ollama> m_ollama;

    mutable std::mutex m_modelsLock;
    std::vector<LlmModel> m_models;

    size_t m_modelIdx;
    size_t m_ctxSize;

    std::atomic<bool> m_exit;
    std::condition_variable m_cv;
    std::thread m_thread;

    mutable std::mutex m_lock;
    std::vector<WorkItem> m_jobs;
    bool m_busy;

    char* m_input;
    std::unique_ptr<ollama::messages> m_chat;

    ImFont* m_font;
    ImFont* m_smallFont;
    ImFont* m_bigFont;
};

}

#endif
