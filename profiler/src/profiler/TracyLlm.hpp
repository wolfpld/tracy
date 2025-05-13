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
#include <json.hpp>

#include "TracyEmbed.hpp"
#include "tracy_robin_hood.h"

class Ollama;

namespace ollama
{
class message;
class messages;
class response;
}

namespace tracy
{

class TracyLlm
{
    enum class Task
    {
        LoadModels,
        SendMessage,
    };

    struct WorkItem
    {
        Task task;
        std::function<void()> callback;
        std::unique_ptr<ollama::messages> chat;
    };

    struct ChatCache
    {
        std::vector<std::string> lines;
        size_t parsedLen;
    };

    struct LineContext
    {
        bool codeBlock;
    };

public:
    struct LlmModel
    {
        std::string name;
        int ctxSize;
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

    void ResetChat();

    void SendMessage( ollama::messages&& messages );
    bool OnResponse( const ollama::response& response );

    void UpdateCache( ChatCache& cache, const std::string& str );

    void PrintLine( LineContext& ctx, const std::string& str, int num );
    void CleanContext( LineContext& ctx);

    std::unique_ptr<Ollama> m_ollama;

    mutable std::mutex m_modelsLock;
    std::vector<LlmModel> m_models;

    size_t m_modelIdx;

    std::atomic<bool> m_exit;
    std::condition_variable m_cv;
    std::thread m_thread;

    mutable std::mutex m_lock;
    std::vector<WorkItem> m_jobs;
    bool m_busy = false;
    bool m_responding = false;
    bool m_stop = false;
    bool m_wasUpdated = false;
    bool m_focusInput = false;
    bool m_enableTools = true;

    char* m_input;
    std::unique_ptr<ollama::messages> m_chat;
    unordered_flat_map<size_t, ChatCache> m_chatCache;

    ImFont* m_font;
    ImFont* m_smallFont;
    ImFont* m_bigFont;

    std::shared_ptr<EmbedData> m_systemPrompt;
    nlohmann::json m_tools;
};

}

#endif
