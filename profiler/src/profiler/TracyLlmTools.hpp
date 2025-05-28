#ifndef __TRACYLLMTOOLS_HPP__
#define __TRACYLLMTOOLS_HPP__

#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "TracyLlmEmbeddings.hpp"
#include "tracy_robin_hood.h"

class EmbedData;

namespace tracy
{

class TracyLlmApi;

class TracyLlmTools
{
public:
    struct ToolReply
    {
        std::string reply;
        std::string image;
    };

    struct EmbeddingState
    {
        std::string model;
        bool done = false;
        bool inProgress = false;
        float progress = 0;
    };

    TracyLlmTools();
    ~TracyLlmTools();

    ToolReply HandleToolCalls( const std::string& name, const std::vector<std::string>& args, TracyLlmApi& api, int contextSize, bool hasEmbeddingsModel );
    std::string GetCurrentTime() const;

    [[nodiscard]] EmbeddingState GetManualEmbeddingsState() const;
    void BuildManualEmbeddings( const std::string& model, TracyLlmApi& api );
    void CancelManualEmbeddings();

    bool m_netAccess = true;

private:
    [[nodiscard]] int CalcMaxSize() const;
    [[nodiscard]] std::string TrimString( std::string&& str ) const;

    std::string FetchWebPage( const std::string& url, bool cache = true );
    ToolReply SearchWikipedia( std::string query, const std::string& lang );
    std::string GetWikipedia( std::string page, const std::string& lang );
    std::string GetDictionary( std::string word, const std::string& lang );
    std::string SearchWeb( std::string query );
    std::string GetWebpage( const std::string& url );
    std::string SearchManual( const std::string& query, TracyLlmApi& api, bool hasEmbeddingsModel );

    bool TryLoadEmbeddingsCache( const char* file, uint64_t hash );
    void ManualEmbeddingsWorker( TracyLlmApi& api );

    unordered_flat_map<std::string, std::string> m_webCache;

    int m_ctxSize;

    mutable std::mutex m_lock;
    std::thread m_thread;
    bool m_cancel = false;
    EmbeddingState m_manualEmbeddingState;
    std::unique_ptr<TracyLlmEmbeddings> m_manualEmbeddings;

    std::shared_ptr<EmbedData> m_manual;
    std::vector<std::string> m_manualChunks;
    std::vector<std::pair<std::string, int>> m_chunkData;
};

}

#endif
