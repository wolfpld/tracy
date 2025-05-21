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
};

class TracyLlmApi
{
    enum class Type
    {
        Unknown,
        Ollama,
        LmStudio,
    };

public:
    ~TracyLlmApi();

    bool Connect( const char* url );
    bool ChatCompletion( const nlohmann::json& req, const std::function<bool(const nlohmann::json&)>& callback );;

    [[nodiscard]] bool IsConnected() const { return m_curl != nullptr; }
    [[nodiscard]] const std::vector<LlmModel>& GetModels() const { return m_models; }
    [[nodiscard]] int GetContextSize() const { return m_contextSize; }

private:
    int64_t GetRequest( const std::string& url, std::string& response );
    int64_t PostRequest( const std::string& url, const std::string& data, std::string& response );

    void* m_curl = nullptr;
    std::string m_url;
    Type m_type;

    std::vector<LlmModel> m_models;
    int m_contextSize;
};

}

#endif
