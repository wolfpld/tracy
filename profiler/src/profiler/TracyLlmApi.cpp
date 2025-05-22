#include <assert.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <string>

#include "TracyLlmApi.hpp"

namespace tracy
{

static size_t WriteFn( void* _data, size_t size, size_t num, void* ptr )
{
    const auto data = (unsigned char*)_data;
    const auto sz = size*num;
    auto& v = *(std::string*)ptr;
    v.append( (const char*)data, sz );
    return sz;
}


TracyLlmApi::~TracyLlmApi()
{
    if( m_curl ) curl_easy_cleanup( m_curl );
}

void TracyLlmApi::SetupCurl()
{
    curl_easy_setopt( m_curl, CURLOPT_NOSIGNAL, 1L );
    curl_easy_setopt( m_curl, CURLOPT_CA_CACHE_TIMEOUT, 604800L );
    curl_easy_setopt( m_curl, CURLOPT_FOLLOWLOCATION, 1L );
    curl_easy_setopt( m_curl, CURLOPT_TIMEOUT, 300 );
    curl_easy_setopt( m_curl, CURLOPT_USERAGENT, "Tracy Profiler" );
}

bool TracyLlmApi::Connect( const char* url )
{
    m_contextSize = -1;
    m_url = url;
    m_models.clear();
    if( m_curl ) curl_easy_cleanup( m_curl );

    m_curl = curl_easy_init();
    if( !m_curl ) return false;

    SetupCurl();

    std::string buf;
    if( GetRequest( m_url + "/v1/models", buf ) != 200 )
    {
        curl_easy_cleanup( m_curl );
        m_curl = nullptr;
        return false;
    }

    try
    {
        m_type = Type::Unknown;
        nlohmann::json json = nlohmann::json::parse( buf );
        for( auto& model : json["data"] )
        {
            auto& id = model["id"].get_ref<const std::string&>();
            m_models.emplace_back( LlmModel { .name = id } );

            std::string buf2;
            if( GetRequest( m_url + "/api/v0/models/" + id, buf2 ) == 200 )
            {
                m_type = Type::LmStudio;
                auto json2 = nlohmann::json::parse( buf2 );
                if( json2["type"] == "embeddings" )
                {
                    m_models.pop_back();
                    continue;
                }
                m_models.back().quant = json2["quantization"].get_ref<const std::string&>();
                if( json2.contains( "loaded_context_length" ) ) m_models.back().contextSize = json2["loaded_context_length"].get<int>();
            }
            else if( PostRequest( m_url + "/api/show", "{\"name\":\"" + id + "\"}", buf2 ) == 200 )
            {
                m_type = Type::Ollama;
                auto json2 = nlohmann::json::parse( buf2 );
                m_models.back().quant = json2["details"]["quantization_level"].get_ref<const std::string&>();
            }
        }
    }
    catch( const std::exception& e )
    {
        m_models.clear();
        curl_easy_cleanup( m_curl );
        m_curl = nullptr;
        return false;
    }

    return true;
}

struct StreamData
{
    std::string str;
    const std::function<bool(const nlohmann::json&)>& callback;
};

static size_t StreamFn( void* _data, size_t size, size_t num, void* ptr )
{
    auto data = (const char*)_data;
    const auto sz = size*num;
    auto& v = *(StreamData*)ptr;
    v.str.append( data, sz );

    for(;;)
    {
        if( strncmp( v.str.c_str(), "data: [DONE]", 12 ) == 0 ) return sz;

        auto pos = v.str.find( "data: " );
        if( pos == std::string::npos ) break;
        pos += 6;
        auto end = v.str.find( "\n\n", pos );
        if( end == std::string::npos ) break;

        nlohmann::json json = nlohmann::json::parse( v.str.c_str() + pos, v.str.c_str() + end );
        if( !v.callback( json ) ) return CURL_WRITEFUNC_ERROR;
        v.str.erase( 0, end + 2 );
    }
    return sz;
}

bool TracyLlmApi::ChatCompletion( const nlohmann::json& req, const std::function<bool(const nlohmann::json&)>& callback, int modelIdx )
{
    assert( m_curl );
    StreamData data = { .callback = callback };

    const auto url = m_url + "/v1/chat/completions";
    const auto reqStr = req.dump();

    curl_slist *hdr = nullptr;
    hdr = curl_slist_append( hdr, "Accept: application/json" );
    hdr = curl_slist_append( hdr, "Content-Type: application/json" );

    curl_easy_setopt( m_curl, CURLOPT_URL, url.c_str() );
    curl_easy_setopt( m_curl, CURLOPT_HTTPHEADER, hdr );
    curl_easy_setopt( m_curl, CURLOPT_POSTFIELDS, reqStr.c_str() );
    curl_easy_setopt( m_curl, CURLOPT_POSTFIELDSIZE, reqStr.size() );
    curl_easy_setopt( m_curl, CURLOPT_WRITEDATA, &data.str );
    curl_easy_setopt( m_curl, CURLOPT_WRITEFUNCTION, StreamFn );

    auto res = curl_easy_perform( m_curl );
    curl_slist_free_all( hdr );
    if( res != CURLE_OK && res != CURLE_WRITE_ERROR ) return false;

    int64_t http_code = 0;
    curl_easy_getinfo( m_curl, CURLINFO_RESPONSE_CODE, &http_code );
    if( http_code == 200 )
    {
        if( m_type == Type::LmStudio && m_models[modelIdx].contextSize <= 0 )
        {
            curl_easy_reset( m_curl );
            SetupCurl();
            std::string buf;
            if( GetRequest( m_url + "/api/v0/models/" + m_models[modelIdx].name, buf ) == 200 )
            {
                m_models[modelIdx].contextSize = nlohmann::json::parse( buf )["loaded_context_length"].get<int>();
            }
        }
        return true;
    }
    return false;
}

int64_t TracyLlmApi::GetRequest( const std::string& url, std::string& response )
{
    assert( m_curl );
    response.clear();

    curl_easy_setopt( m_curl, CURLOPT_URL, url.c_str() );
    curl_easy_setopt( m_curl, CURLOPT_WRITEDATA, &response );
    curl_easy_setopt( m_curl, CURLOPT_WRITEFUNCTION, WriteFn );

    auto res = curl_easy_perform( m_curl );
    if( res != CURLE_OK ) return -1;

    int64_t http_code = 0;
    curl_easy_getinfo( m_curl, CURLINFO_RESPONSE_CODE, &http_code );
    return http_code;
}

int64_t TracyLlmApi::PostRequest( const std::string& url, const std::string& data, std::string& response )
{
    assert( m_curl );
    response.clear();

    curl_easy_setopt( m_curl, CURLOPT_URL, url.c_str() );
    curl_easy_setopt( m_curl, CURLOPT_POSTFIELDS, data.c_str() );
    curl_easy_setopt( m_curl, CURLOPT_POSTFIELDSIZE, data.size() );
    curl_easy_setopt( m_curl, CURLOPT_WRITEDATA, &response );
    curl_easy_setopt( m_curl, CURLOPT_WRITEFUNCTION, WriteFn );

    auto res = curl_easy_perform( m_curl );
    if( res != CURLE_OK ) return -1;

    int64_t http_code = 0;
    curl_easy_getinfo( m_curl, CURLINFO_RESPONSE_CODE, &http_code );
    return http_code;
}

}
