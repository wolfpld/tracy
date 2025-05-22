#ifndef __TRACYLLM_HPP__
#define __TRACYLLM_HPP__

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

#include "TracyEmbed.hpp"
#include "TracyLlmTools.hpp"
#include "tracy_robin_hood.h"

namespace tracy
{

class TracyLlmApi;

class TracyLlm
{
    enum class Task
    {
        Connect,
        SendMessage,
    };

    struct WorkItem
    {
        Task task;
        std::function<void()> callback;
        std::vector<nlohmann::json> chat;
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
    TracyLlm();
    ~TracyLlm();

    [[nodiscard]] bool IsBusy() const { std::lock_guard lock( m_lock); return m_busy; }

    void Draw();

    bool m_show = false;

private:
    void Worker();

    void LoadModels();
    void UpdateModels();

    void ResetChat();

    void SendMessage( const std::vector<nlohmann::json>& messages );
    bool OnResponse( const nlohmann::json& json );

    void UpdateCache( ChatCache& cache, const std::string& str );

    void PrintLine( LineContext& ctx, const std::string& str, int num );
    void PrintMarkdown( const char* str );
    void CleanContext( LineContext& ctx);

    std::unique_ptr<TracyLlmApi> m_api;

    int m_modelIdx;
    int m_embedIdx;

    std::atomic<bool> m_exit;
    std::condition_variable m_cv;
    std::thread m_thread;

    mutable std::mutex m_lock;
    std::vector<WorkItem> m_jobs;
    bool m_busy = false;
    bool m_responding = false;
    bool m_stop = false;
    bool m_focusInput = false;
    int m_chatId = 0;
    int m_usedCtx = 0;
    float m_temperature = 1.0f;
    bool m_setTemperature = false;

    char* m_input;
    char* m_apiInput;
    std::vector<nlohmann::json> m_chat;
    unordered_flat_map<size_t, ChatCache> m_chatCache;

    std::shared_ptr<EmbedData> m_systemPrompt;

    TracyLlmTools m_tools;
};

}

#endif
