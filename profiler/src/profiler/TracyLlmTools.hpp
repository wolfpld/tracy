#ifndef __TRACYLLMTOOLS_HPP__
#define __TRACYLLMTOOLS_HPP__

#include <string>
#include <vector>

#include "tracy_robin_hood.h"

namespace tracy
{

class TracyLlmTools
{
public:
    struct ToolReply
    {
        std::string reply;
        std::string image;
    };

    void SetModelMaxContext( int modelMaxContext );

    ToolReply HandleToolCalls( const std::string& name, const std::vector<std::string>& args );
    std::string GetCurrentTime();

    bool m_netAccess = true;

private:
    [[nodiscard]] int CalcMaxSize() const;

    std::string FetchWebPage( const std::string& url );
    ToolReply SearchWikipedia( std::string query, const std::string& lang );
    std::string GetWikipedia( std::string page, const std::string& lang );
    std::string SearchWeb( std::string query );

    unordered_flat_map<std::string, std::string> m_webCache;

    int m_modelMaxContext = 0;
};

}

#endif
