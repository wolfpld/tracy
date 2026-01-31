#ifndef __TRACYLLMTOOLS_HPP__
#define __TRACYLLMTOOLS_HPP__

#include <nlohmann/json.hpp>
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
class TracyManualData;
class Worker;

class TracyLlmTools
{
public:
    struct EmbeddingState
    {
        std::string model;
        bool done = false;
        bool inProgress = false;
        float progress = 0;
    };

    TracyLlmTools( Worker& worker, const TracyManualData& manual );
    ~TracyLlmTools();

    std::string HandleToolCalls( const std::string& tool, const nlohmann::json& json, TracyLlmApi& api, int contextSize, bool hasEmbeddingsModel );
    std::string GetCurrentTime() const;

    [[nodiscard]] EmbeddingState GetManualEmbeddingsState() const;
    void SelectManualEmbeddings( const std::string& model );
    void BuildManualEmbeddings( const std::string& model, TracyLlmApi& api );
    void CancelManualEmbeddings();

    bool m_netAccess = true;

private:
    [[nodiscard]] int CalcMaxSize() const;
    [[nodiscard]] std::string TrimString( std::string&& str ) const;

    std::string FetchWebPage( const std::string& url, bool cache = true );
    std::string SearchWikipedia( std::string query, const std::string& lang );
    std::string GetWikipedia( std::string page, const std::string& lang );
    std::string GetDictionary( std::string word, const std::string& lang );
    std::string SearchWeb( std::string query );
    std::string GetWebpage( const std::string& url );
    std::string SearchManual( const std::string& query, TracyLlmApi& api, bool hasEmbeddingsModel );
    std::string SourceFile( const std::string& file, uint32_t line, uint32_t context, uint32_t contextBack ) const;
    std::string SourceSearch( std::string query, bool caseInsensitive, const std::string& path ) const;

    void ManualEmbeddingsWorker( TracyLlmApi& api );

    unordered_flat_map<std::string, std::string> m_webCache;

    int m_ctxSize;

    mutable std::mutex m_lock;
    std::thread m_thread;
    bool m_cancel = false;
    EmbeddingState m_manualEmbeddingState;
    std::unique_ptr<TracyLlmEmbeddings> m_manualEmbeddings;

    std::vector<std::pair<std::string, uint32_t>> m_chunkData;

    Worker& m_worker;
    const TracyManualData& m_manual;
};

}

#endif
