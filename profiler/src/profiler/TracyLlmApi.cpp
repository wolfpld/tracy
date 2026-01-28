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

void TracyLlmApi::SetupCurl( void* curl )
{
    curl_easy_setopt( curl, CURLOPT_NOSIGNAL, 1L );
    curl_easy_setopt( curl, CURLOPT_CA_CACHE_TIMEOUT, 604800L );
    curl_easy_setopt( curl, CURLOPT_FOLLOWLOCATION, 1L );
    curl_easy_setopt( curl, CURLOPT_TIMEOUT, 1200 );
    curl_easy_setopt( curl, CURLOPT_USERAGENT, "Tracy Profiler" );
}

bool TracyLlmApi::Connect( const char* url )
{
    m_url = url;
    m_models.clear();
    if( m_curl ) curl_easy_cleanup( m_curl );

    m_curl = curl_easy_init();
    if( !m_curl ) return false;

    SetupCurl( m_curl );

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
            if( ( m_type == Type::Unknown || m_type == Type::LlamaSwap ) && GetRequest( m_url + "/running", buf2 ) == 200 && buf2.starts_with( "{\"running\":" ) )
            {
                m_type = Type::LlamaSwap;
                if( id.find( "embed" ) != std::string::npos ) m_models.back().embeddings = true;
            }
            else if( ( m_type == Type::Unknown || m_type == Type::LmStudio ) && GetRequest( m_url + "/api/v0/models/" + id, buf2 ) == 200 )
            {
                m_type = Type::LmStudio;
                auto json2 = nlohmann::json::parse( buf2 );
                if( json2["type"] == "embeddings" ) m_models.back().embeddings = true;
                m_models.back().quant = json2["quantization"].get_ref<const std::string&>();
                if( json2.contains( "loaded_context_length" ) ) m_models.back().contextSize = json2["loaded_context_length"].get<int>();
            }
            else if( m_type == Type::Unknown )
            {
                m_type = Type::Other;
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

    std::ranges::sort( m_models, []( const auto& a, const auto& b ) { return a.name < b.name; } );

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

        auto err = v.str.find( "error: " );
        if( err != std::string::npos )
        {
            err += 7;
            auto end = v.str.find( "\n\n", err );
            if( end == std::string::npos ) break;
            throw std::runtime_error( v.str.substr( err, end - err ) );
        }
        else
        {
            auto pos = v.str.find( "data: " );
            if( pos == std::string::npos ) break;
            pos += 6;
            auto end = v.str.find( "\n\n", pos );
            if( end == std::string::npos ) break;

            nlohmann::json json = nlohmann::json::parse( v.str.c_str() + pos, v.str.c_str() + end );
            if( !v.callback( json ) ) return CURL_WRITEFUNC_ERROR;
            v.str.erase( 0, end + 2 );
        }
    }
    return sz;
}

bool TracyLlmApi::ChatCompletion( const nlohmann::json& req, const std::function<bool(const nlohmann::json&)>& callback, int modelIdx )
{
    assert( m_curl );
    StreamData data = { .callback = callback };

    const auto url = m_url + "/v1/chat/completions";
    const auto reqStr = req.dump( -1, ' ', false, nlohmann::json::error_handler_t::replace );

    curl_slist *hdr = nullptr;
    hdr = curl_slist_append( hdr, "Accept: application/json" );
    hdr = curl_slist_append( hdr, "Content-Type: application/json" );

    curl_easy_setopt( m_curl, CURLOPT_URL, url.c_str() );
    curl_easy_setopt( m_curl, CURLOPT_HTTPHEADER, hdr );
    curl_easy_setopt( m_curl, CURLOPT_POSTFIELDS, reqStr.c_str() );
    curl_easy_setopt( m_curl, CURLOPT_POSTFIELDSIZE, reqStr.size() );
    curl_easy_setopt( m_curl, CURLOPT_WRITEDATA, &data.str );
    curl_easy_setopt( m_curl, CURLOPT_WRITEFUNCTION, StreamFn );

    CURLcode res;
    try
    {
        res = curl_easy_perform( m_curl );
    }
    catch( const std::exception& e )
    {
        curl_easy_cleanup( m_curl );
        curl_slist_free_all( hdr );
        m_curl = curl_easy_init();
        SetupCurl( m_curl );
        throw;
    }

    curl_slist_free_all( hdr );
    if( res != CURLE_OK && res != CURLE_WRITE_ERROR ) return false;

    int64_t http_code = 0;
    curl_easy_getinfo( m_curl, CURLINFO_RESPONSE_CODE, &http_code );
    if( http_code == 200 )
    {
        if( m_models[modelIdx].contextSize <= 0 )
        {
            if( m_type == Type::LlamaSwap )
            {
                curl_easy_reset( m_curl );
                SetupCurl( m_curl );
                std::string buf;
                if( GetRequest( m_url + "/upstream/" + m_models[modelIdx].name + "/props", buf ) == 200 )
                {
                    auto json = nlohmann::json::parse( buf );
                    if( json.contains( "default_generation_settings" ) )
                    {
                        auto& settings = json["default_generation_settings"];
                        if( settings.contains( "n_ctx" ) ) m_models[modelIdx].contextSize = settings["n_ctx"].get<int>();
                    }
                }
            }
            else if( m_type == Type::LmStudio )
            {
                curl_easy_reset( m_curl );
                SetupCurl( m_curl );
                std::string buf;
                if( GetRequest( m_url + "/api/v0/models/" + m_models[modelIdx].name, buf ) == 200 )
                {
                    auto json = nlohmann::json::parse( buf );
                    if( json.contains( "loaded_context_length" ) ) m_models[modelIdx].contextSize = json["loaded_context_length"].get<int>();
                }
            }
        }
        return true;
    }
    else
    {
        auto str = std::move( data.str );
        data.str.clear();
        throw std::runtime_error( "HTTP error " + std::to_string( http_code ) + ": " + str );
    }
}

bool TracyLlmApi::Embeddings( const nlohmann::json& req, nlohmann::json& response, bool separateConnection )
{
    assert( m_curl );

    std::string buf;
    auto res = PostRequest( m_url + "/v1/embeddings", req.dump( -1, ' ', false, nlohmann::json::error_handler_t::replace ), buf, separateConnection );
    if( res != 200 ) return false;

    response = nlohmann::json::parse( buf );
    return true;
}

int TracyLlmApi::Tokenize( const std::string& text, int modelIdx )
{
    if( m_type == Type::LlamaSwap )
    {
        std::string buf;
        nlohmann::json req = { { "content", text } };
        auto res = PostRequest( m_url + "/upstream/" + m_models[modelIdx].name + "/tokenize", req.dump( -1, ' ', false, nlohmann::json::error_handler_t::replace ), buf, true );
        if( res != 200 ) return -1;

        try
        {
            auto json = nlohmann::json::parse( buf );
            return json["tokens"].size();
        }
        catch( const std::exception& )
        {
            return -1;
        }
    }

    return -1;
}

nlohmann::json TracyLlmApi::SendMessage( const nlohmann::json& chat, int modelIdx )
{
    assert( m_curl );

    nlohmann::json req = {
        { "model", m_models[modelIdx].name },
        { "messages", chat }
    };

    auto data = req.dump( -1, ' ', false, nlohmann::json::error_handler_t::replace );
    std::string buf;
    auto res = PostRequest( m_url + "/v1/chat/completions", data, buf, true );

    try
    {
        return nlohmann::json::parse( buf );
    }
    catch( const std::exception& )
    {
        return { { "response", buf } };
    }
}

int64_t TracyLlmApi::GetRequest( const std::string& url, std::string& response )
{
    assert( m_curl );
    response.clear();

    curl_slist *hdr = nullptr;
    hdr = curl_slist_append( hdr, "Accept: application/json" );
    hdr = curl_slist_append( hdr, "Content-Type: application/json" );

    curl_easy_setopt( m_curl, CURLOPT_URL, url.c_str() );
    curl_easy_setopt( m_curl, CURLOPT_HTTPHEADER, hdr );
    curl_easy_setopt( m_curl, CURLOPT_WRITEDATA, &response );
    curl_easy_setopt( m_curl, CURLOPT_WRITEFUNCTION, WriteFn );

    auto res = curl_easy_perform( m_curl );
    curl_slist_free_all( hdr );
    if( res != CURLE_OK ) return -1;

    int64_t http_code = 0;
    curl_easy_getinfo( m_curl, CURLINFO_RESPONSE_CODE, &http_code );
    return http_code;
}

int64_t TracyLlmApi::PostRequest( const std::string& url, const std::string& data, std::string& response, bool separateConnection )
{
    assert( m_curl );
    response.clear();

    curl_slist *hdr = nullptr;
    hdr = curl_slist_append( hdr, "Accept: application/json" );
    hdr = curl_slist_append( hdr, "Content-Type: application/json" );

    auto curl = m_curl;
    if( separateConnection )
    {
        curl = curl_easy_init();
        if( !curl ) return -1;
        SetupCurl( curl );
    }

    curl_easy_setopt( curl, CURLOPT_URL, url.c_str() );
    curl_easy_setopt( curl, CURLOPT_HTTPHEADER, hdr );
    curl_easy_setopt( curl, CURLOPT_POSTFIELDS, data.c_str() );
    curl_easy_setopt( curl, CURLOPT_POSTFIELDSIZE, data.size() );
    curl_easy_setopt( curl, CURLOPT_WRITEDATA, &response );
    curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, WriteFn );

    auto res = curl_easy_perform( curl );
    curl_slist_free_all( hdr );
    if( res != CURLE_OK )
    {
        if( separateConnection ) curl_easy_cleanup( curl );
        return -1;
    }

    int64_t http_code = 0;
    curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, &http_code );
    if( separateConnection ) curl_easy_cleanup( curl );
    return http_code;
}

}
