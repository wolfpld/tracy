#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <libbase64.h>
#include <pugixml.hpp>
#include <tidy.h>
#include <tidybuffio.h>
#include <time.h>

#include "TracyLlmApi.hpp"
#include "TracyLlmTools.hpp"

constexpr const char* NoNetworkAccess = "Internet access is disabled by the user. You may inform the user that he can enable it in the settings, so that you can use the tools to gather information.";

#define NetworkCheckString if( !m_netAccess ) return NoNetworkAccess
#define NetworkCheckReply if( !m_netAccess ) return { .reply = NoNetworkAccess }

namespace tracy
{

static std::string UrlEncode( const std::string& str )
{
    std::string out;
    out.reserve( str.size() * 3 );

    constexpr char hex[] = "0123456789ABCDEF";

    for( char c : str )
    {
        if( ( c >= 'a' && c <= 'z' ) ||
            ( c >= 'A' && c <= 'Z' ) ||
            ( c >= '0' && c <= '9' ) ||
              c == '-' || c == '.' || c == '_' || c == '~' )
        {
            out += c;
        }
        else
        {
            out += '%';
            out += hex[(unsigned char)c >> 4];
            out += hex[(unsigned char)c & 0x0F];
        }
    }
    return out;
}

TracyLlmTools::ToolReply TracyLlmTools::HandleToolCalls( const std::string& name, const std::vector<std::string>& args, const TracyLlmApi& api)
{
    m_ctxSize = api.GetContextSize();

    if( name == "fetch_web_page" )
    {
        if( args.empty() ) return { .reply = "Missing URL argument" };
        return { .reply = FetchWebPage( args[0] ) };
    }
    if( name == "search_wikipedia" )
    {
        if( args.empty() ) return { .reply = "Missing search term argument" };
        if( args.size() < 2 ) return { .reply = "Missing language argument" };
        return SearchWikipedia( args[0], args[1] );
    }
    if( name == "get_wikipedia" )
    {
        if( args.empty() ) return { .reply = "Missing page name argument" };
        if( args.size() < 2 ) return { .reply = "Missing language argument" };
        return { .reply = GetWikipedia( args[0], args[1] ) };
    }
    if( name == "get_dictionary" )
    {
        if( args.empty() ) return { .reply = "Missing word argument" };
        if( args.size() < 2 ) return { .reply = "Missing language argument" };
        return { .reply = GetDictionary( args[0], args[1] ) };
    }
    if( name == "search_web" )
    {
        if( args.empty() ) return { .reply = "Missing search term argument" };
        return { .reply = SearchWeb( args[0] ) };
    }
    return { .reply = "Unknown tool call: " + name };
}

std::string TracyLlmTools::GetCurrentTime()
{
    auto t = time( nullptr );
    auto tm = localtime( &t );

    char buffer[64];
    strftime( buffer, sizeof( buffer ), "%Y-%m-%d %H:%M:%S", tm );

    return buffer;
}

int TracyLlmTools::CalcMaxSize() const
{
    if( m_ctxSize <= 0 ) return 32*1024;

    // Limit the size of the response to avoid exceeding the context size
    // Assume average token size is 4 bytes. Make space for 3 articles to be retrieved.
    const auto maxSize = ( m_ctxSize * 4 ) / 3;
    return maxSize;
}

static size_t WriteFn( void* _data, size_t size, size_t num, void* ptr )
{
    const auto data = (unsigned char*)_data;
    const auto sz = size*num;
    auto& v = *(std::string*)ptr;
    v.append( (const char*)data, sz );
    return sz;
}

std::string TracyLlmTools::FetchWebPage( const std::string& url )
{
    auto it = m_webCache.find( url );
    if( it != m_webCache.end() ) return it->second;

    auto curl = curl_easy_init();
    if( !curl ) return "Error: Failed to initialize cURL";

    std::string buf;

    curl_easy_setopt( curl, CURLOPT_NOSIGNAL, 1L );
    curl_easy_setopt( curl, CURLOPT_URL, url.c_str() );
    curl_easy_setopt( curl, CURLOPT_CA_CACHE_TIMEOUT, 604800L );
    curl_easy_setopt( curl, CURLOPT_FOLLOWLOCATION, 1L );
    curl_easy_setopt( curl, CURLOPT_TIMEOUT, 10 );
    curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, WriteFn );
    curl_easy_setopt( curl, CURLOPT_WRITEDATA, &buf );
    curl_easy_setopt( curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36" );

    auto res = curl_easy_perform( curl );

    std::string response;
    if( res != CURLE_OK )
    {
        response = "Error: " + std::string( curl_easy_strerror( res ) );
    }
    else
    {
        response = std::move( buf );
    }
    m_webCache.emplace( url, response );

    curl_easy_cleanup( curl );
    return response;
}

TracyLlmTools::ToolReply TracyLlmTools::SearchWikipedia( std::string query, const std::string& lang )
{
    NetworkCheckReply;

    std::ranges::replace( query, ' ', '+' );
    const auto response = FetchWebPage( "https://" + lang + ".wikipedia.org/w/rest.php/v1/search/page?q=" + UrlEncode( query ) + "&limit=1" );

    auto json = nlohmann::json::parse( response );
    if( !json.contains( "pages" ) ) return { .reply = "No results found" };

    auto& page = json["pages"];
    if( page.size() == 0 ) return { .reply = "No results found" };

    auto& page0 = page[0];
    if( !page0.contains( "key" ) ) return { .reply = "No results found" };

    const auto key = page0["key"].get_ref<const std::string&>();

    auto summary = FetchWebPage( "https://" + lang + ".wikipedia.org/api/rest_v1/page/summary/" + key );
    auto summaryJson = nlohmann::json::parse( summary );

    if( !summaryJson.contains( "title" ) ) return { .reply = "No results found" };

    nlohmann::json output;
    output["key"] = key;
    output["title"] = summaryJson["title"];
    if( summaryJson.contains( "description" ) ) output["description"] = summaryJson["description"];
    output["extract"] = summaryJson["extract"];

    std::string image;
    if( summaryJson.contains( "thumbnail" ) )
    {
        auto& thumb = summaryJson["thumbnail"];
        if( thumb.contains( "source" ) )
        {
            auto imgData = FetchWebPage( thumb["source"].get_ref<const std::string&>() );
            if( !imgData.empty() && imgData[0] != '<' && strncmp( imgData.c_str(), "Error:", 6 ) != 0 )
            {
                size_t b64sz = ( ( 4 * imgData.size() / 3 ) + 3 ) & ~3;
                char* b64 = new char[b64sz+1];
                b64[b64sz] = 0;
                size_t outSz;
                base64_encode( (const char*)imgData.data(), imgData.size(), b64, &outSz, 0 );
                image = std::string( b64, outSz );
                delete[] b64;
            }
        }
    }

    const auto reply = output.dump( 2 );
    return { .reply = reply, .image = image };
}

std::string TracyLlmTools::GetWikipedia( std::string page, const std::string& lang )
{
    NetworkCheckString;

    std::ranges::replace( page, ' ', '_' );
    auto res = FetchWebPage( "https://" + lang + ".wikipedia.org/w/rest.php/v1/page/" + page );

    const auto maxSize = CalcMaxSize();
    if( res.size() > maxSize ) res = res.substr( 0, maxSize );
    return res;
}

std::string TracyLlmTools::GetDictionary( std::string word, const std::string& lang )
{
    NetworkCheckString;

    std::ranges::replace( word, ' ', '+' );
    const auto response = FetchWebPage( "https://" + lang + ".wiktionary.org/w/rest.php/v1/search/page?q=" + UrlEncode( word ) + "&limit=1" );

    auto json = nlohmann::json::parse( response );
    if( !json.contains( "pages" ) ) return "No results found";

    auto& page = json["pages"];
    if( page.size() == 0 ) return "No results found";

    auto& page0 = page[0];
    if( !page0.contains( "key" ) ) return "No results found";

    const auto key = page0["key"].get_ref<const std::string&>();
    auto res = FetchWebPage( "https://" + lang + ".wiktionary.org/w/rest.php/v1/page/" + key );

    const auto maxSize = CalcMaxSize();
    if( res.size() > maxSize ) res = res.substr( 0, maxSize );
    return res;
}

static std::string RemoveNewline( std::string str )
{
    std::erase( str, '\r' );
    std::ranges::replace( str, '\n', ' ' );
    return str;
}

std::string TracyLlmTools::SearchWeb( std::string query )
{
    NetworkCheckString;

    std::ranges::replace( query, ' ', '+' );
    const auto response = FetchWebPage( "https://lite.duckduckgo.com/lite?q=" + UrlEncode( query ) );

    TidyBuffer err = {};
    tidyBufInit( &err );

    TidyDoc td = tidyCreate();
    tidyOptSetBool( td, TidyXhtmlOut, yes );
    tidyOptSetBool( td, TidyLowerLiterals, yes );
    tidyOptSetBool( td, TidyMark, no );
    tidyOptSetBool( td, TidyHideComments, yes );
    tidySetErrorBuffer( td, &err );

    if( tidyParseString( td, response.c_str() ) == 2 )
    {
        auto out = std::string( (const char*)err.bp );
        tidyBufFree( &err );
        tidyRelease( td );
        return out;
    }

    TidyBuffer buf = {};
    tidyBufInit( &buf );
    tidyCleanAndRepair( td );
    tidySaveBuffer( td, &buf );

    auto tidy = std::string( (const char*)buf.bp );

    tidyBufFree( &buf );
    tidyBufFree( &err );
    tidyRelease( td );

    auto doc = std::make_unique<pugi::xml_document>();
    if( !doc->load_string( tidy.c_str() ) )
    {
        return "Error: Failed to parse HTML";
    }

    const auto titles = doc->select_nodes( "//a[@class='result-link']" );
    const auto snippets = doc->select_nodes( "//td[@class='result-snippet']" );
    const auto urls = doc->select_nodes( "//span[@class='link-text']" );

    const auto sz = titles.size();
    if( sz != snippets.size() || sz != urls.size() )
    {
        return "Error: Failed to parse HTML";
    }

    nlohmann::json json;

    for( size_t i = 0; i < sz; i++ )
    {
        auto title = titles[i].node();
        auto snippet = snippets[i].node();
        auto url = urls[i].node();

        nlohmann::json result;
        result["title"] = RemoveNewline( title.text().as_string() );
        result["snippet"] = RemoveNewline( snippet.text().as_string() );
        result["url"] = RemoveNewline( url.text().as_string() );

        json[i] = result;
    }

    return json.dump( 2 );
}

}
