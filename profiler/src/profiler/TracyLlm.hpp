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

namespace tracy
{

class TracyLlmApi;
class TracyLlmChat;
class TracyLlmTools;
class TracyManualData;
class Worker;

class TracyLlm
{
    enum class Task
    {
        Connect,
        SendMessage,
        Tokenize
    };

    struct WorkItem
    {
        Task task;
        std::function<void()> callback;
        std::function<void(nlohmann::json)> callback2;
        std::string param;
        bool stop;
    };

public:
    TracyLlm( Worker& worker, const TracyManualData& manual );
    ~TracyLlm();

    [[nodiscard]] bool IsBusy() const { std::lock_guard lock( m_lock ); return m_busy; }

    void Draw();
    void AddAttachment( std::string&& str, const char* role );
    void AddMessage( std::string&& str, const char* role );
    bool QueueSendMessage();

    bool m_show = false;

private:
    void WorkerThread();

    void UpdateModels();
    void ResetChat();
    void UpdateSystemPrompt();

    void QueueConnect();

    void AddMessageBlocking( std::string&& str, const char* role, std::unique_lock<std::mutex>& lock );
    void AddMessageBlocking( nlohmann::json&& json, std::unique_lock<std::mutex>& lock );

    void ManageContext( std::unique_lock<std::mutex>& lock );
    void SendMessage( std::unique_lock<std::mutex>& lock );

    void AppendResponse( const char* name, const nlohmann::json& delta );
    bool OnResponse( const nlohmann::json& json );

    std::unique_ptr<TracyLlmApi> m_api;
    std::unique_ptr<TracyLlmChat> m_chatUi;
    std::unique_ptr<TracyLlmTools> m_tools;

    int m_modelIdx;
    int m_embedIdx;

    std::atomic<bool> m_exit;
    std::condition_variable m_cv;
    std::thread m_thread;

    mutable std::mutex m_lock;
    std::vector<std::shared_ptr<WorkItem>> m_jobs;
    std::shared_ptr<WorkItem> m_currentJob;

    bool m_busy = false;
    bool m_focusInput = false;
    int m_chatId = 0;
    int m_usedCtx = 0;
    float m_temperature = 1.0f;
    bool m_setTemperature = false;
    bool m_allThinkingRegions = false;

    char* m_input;
    char* m_apiInput;
    std::vector<nlohmann::json> m_chat;

    std::shared_ptr<EmbedData> m_systemPrompt;
    nlohmann::json m_toolsJson;
};

}

#endif
