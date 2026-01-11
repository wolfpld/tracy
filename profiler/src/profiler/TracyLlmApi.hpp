#ifndef __TRACYLLMAPI_HPP__
#define __TRACYLLMAPI_HPP__

#include <functional>
#include <nlohmann/json.hpp>
#include <stdint.h>
#include <string>
#include <vector>

namespace tracy
{

struct LlmModel
{
    std::string name;
    std::string quant;
    int contextSize = -1;
    bool embeddings = false;
};

class TracyLlmApi
{
    enum class Type
    {
        Unknown,
        LmStudio,
        LlamaSwap,
        Other
    };

public:
    ~TracyLlmApi();

    bool Connect( const char* url );
    bool ChatCompletion( const nlohmann::json& req, const std::function<bool(const nlohmann::json&)>& callback, int modelIdx );
    bool Embeddings( const nlohmann::json& req, nlohmann::json& response, bool separateConnection = false );
    [[nodiscard]] int Tokenize( const std::string& text, int modelIdx );
    [[nodiscard]] nlohmann::json SendMessage( const nlohmann::json& chat, int modelIdx );

    [[nodiscard]] bool IsConnected() const { return m_curl != nullptr; }
    [[nodiscard]] const std::vector<LlmModel>& GetModels() const { return m_models; }

private:
    void SetupCurl( void* curl );

    int64_t GetRequest( const std::string& url, std::string& response );
    int64_t PostRequest( const std::string& url, const std::string& data, std::string& response, bool separateConnection = false );

    void* m_curl = nullptr;
    std::string m_url;
    Type m_type;

    std::vector<LlmModel> m_models;
};

}

#endif
