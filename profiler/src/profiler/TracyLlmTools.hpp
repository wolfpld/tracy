#ifndef __TRACYLLMTOOLS_HPP__
#define __TRACYLLMTOOLS_HPP__

#include <nlohmann/json.hpp>
#include <memory>
#include <string>
#include <vector>

#include "TracyLlmBm25.hpp"
#include "tracy_robin_hood.h"

class EmbedData;

namespace tracy
{

struct LlmSkill;
class View;
class Worker;

class TracyLlmTools
{
public:
    TracyLlmTools( Worker& worker, const View& view, const std::vector<LlmSkill>& skills );
    ~TracyLlmTools();

    std::string HandleToolCalls( const std::string& tool, const nlohmann::json& json, int contextSize );
    std::string GetCurrentTime() const;

    static int CalcCtxBasedLimit( int ctxSize );

    bool m_netAccess = true;

private:
    [[nodiscard]] int CalcMaxSize() const;
    [[nodiscard]] std::string TrimString( std::string&& str ) const;

    std::string FetchHttp( const std::string& url, const std::vector<const char*>& headers = {}, bool cache = true );
    std::string SearchWikipedia( std::string query, const std::string& lang );
    std::string GetWikipedia( std::string page, const std::string& lang );
    std::string GetDictionary( std::string word, const std::string& lang );
    std::string SearchWeb( std::string query );
    std::string SearchWebGoogle( std::string query );
    std::string SearchWebBrave( std::string query );
    std::string SearchWebDuckDuckGo( std::string query );
    std::string GetWebpage( const std::string& url );
    std::string SearchManual( const std::string& query );
    std::string SourceFile( const std::string& file, uint32_t line, uint32_t context, uint32_t contextBack ) const;
    std::string SourceSearch( std::string query, bool caseInsensitive, const std::string& path ) const;
    std::string GetSkill( const std::string& name ) const;
    std::string SymbolDisasm( const std::string& address ) const;
    std::string SymbolParents( const std::string& address, uint32_t limit, const std::string& mode ) const;
    std::string SamplingStats( const std::string& query, uint32_t limit ) const;

    unordered_flat_map<std::string, std::string> m_webCache;

    int m_ctxSize;

    std::unique_ptr<TracyLlmBm25> m_manualSearch;

    Worker& m_worker;
    const View& m_view;

    const std::vector<LlmSkill>& m_skills;
};

}

#endif
