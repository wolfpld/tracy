#include <algorithm>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <libbase64.h>
#include <pugixml.hpp>
#include <string_view>
#include <tidy.h>
#include <tidybuffio.h>
#include <time.h>

#include "TracyConfig.hpp"
#include "TracyLlmApi.hpp"
#include "TracyLlmTools.hpp"
#include "TracyManualData.hpp"
#include "TracyStorage.hpp"
#include "TracyUtility.hpp"
#include "TracyWorker.hpp"

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

static std::unique_ptr<pugi::xml_document> ParseHtml( const std::string& html )
{
    TidyDoc td = tidyCreate();
    tidyOptSetBool( td, TidyXhtmlOut, yes );
    tidyOptSetBool( td, TidyLowerLiterals, yes );
    tidyOptSetBool( td, TidyMark, no );
    tidyOptSetBool( td, TidyHideComments, yes );
    tidyOptSetBool( td, TidyShowWarnings, no );
    tidyOptSetInt( td, TidyShowErrors, 0 );
    tidyOptSetBool( td, TidyForceOutput, yes );

    tidyParseString( td, html.c_str() );

    TidyBuffer buf = {};
    tidyBufInit( &buf );
    tidyCleanAndRepair( td );
    tidySaveBuffer( td, &buf );

    auto tidy = std::string( (const char*)buf.bp );

    tidyBufFree( &buf );
    tidyRelease( td );

    auto doc = std::make_unique<pugi::xml_document>();
    if( !doc->load_string( tidy.c_str() ) ) return nullptr;
    return doc;
}

TracyLlmTools::TracyLlmTools( Worker& worker, const TracyManualData& manual )
    : m_worker( worker )
    , m_manual( manual )
{
    int idx = 0;
    for( auto& chunk : m_manual.GetChunks() )
    {
        std::string hdr;
        if( !chunk.section.empty() ) hdr += "Section " + chunk.section;
        if( !chunk.title.empty() )
        {
            if( !chunk.section.empty() ) hdr += ": ";
            hdr += chunk.title;
        }
        hdr += '\n';

        for( auto& line : SplitLines( chunk.text.c_str(), chunk.text.size() ) )
        {
            if( line.empty() ) continue;
            if( line == "---" || line == ":::" || line == "::: bclogo" ) continue;
            m_chunkData.emplace_back( hdr + line, idx );
        }
        idx++;
    }
}

TracyLlmTools::~TracyLlmTools()
{
    CancelManualEmbeddings();
}

template<typename T>
static T GetParam( const nlohmann::json& json, const char* name )
{
    if( !json.contains( name ) ) throw std::runtime_error( "Error: missing parameter: " + std::string( name ) );
    if constexpr( std::is_reference_v<T> )
    {
        return json[name].get_ref<T>();
    }
    else
    {
        return json[name].get<T>();
    }
}

template<typename T>
static T GetParamOpt( const nlohmann::json& json, const char* name, T def )
{
    if( !json.contains( name ) ) return def;
    return json[name].get<T>();
}

#define Param(name) GetParam<const std::string&>( json, name )
#define ParamU32(name) GetParam<uint32_t>( json, name )
#define ParamOptU32(name, def) GetParamOpt<uint32_t>( json, name, def )
#define ParamOptBool(name, def) GetParamOpt<bool>( json, name, def )

TracyLlmTools::ToolReply TracyLlmTools::HandleToolCalls( const std::string& tool, const nlohmann::json& json, TracyLlmApi& api, int contextSize, bool hasEmbeddingsModel )
{
    m_ctxSize = contextSize;

    try
    {
        if( tool == "search_wikipedia" )
        {
            return SearchWikipedia( Param( "query" ), Param( "language" ) );
        }
        else if( tool == "get_wikipedia" )
        {
            return { .reply = GetWikipedia( Param( "page" ), Param( "language" ) ) };
        }
        else if( tool == "get_dictionary" )
        {
            return { .reply = GetDictionary( Param( "word" ), Param( "language" ) ) };
        }
        else if( tool == "search_web" )
        {
            return { .reply = SearchWeb( Param( "query" ) ) };
        }
        else if( tool == "get_webpage" )
        {
            return { .reply = GetWebpage( Param( "url" ) ) };
        }
        else if( tool == "user_manual" )
        {
            return { .reply = SearchManual( Param( "query" ), api, hasEmbeddingsModel ) };
        }
        else if( tool == "source_file" )
        {
            return { .reply = SourceFile( Param( "file" ), ParamU32( "line" ), ParamOptU32( "context", 50 ) ) };
        }
        else if( tool == "source_search" )
        {
            return { .reply = SourceSearch( Param( "query" ), ParamOptBool( "case_insensitive", false ) ) };
        }
        return { .reply = "Unknown tool call: " + tool };
    }
    catch( const std::exception& e )
    {
        return { .reply = e.what() };
    }
}

#undef Param

std::string TracyLlmTools::GetCurrentTime() const
{
    auto t = time( nullptr );
    auto tm = localtime( &t );

    char buffer[64];
    strftime( buffer, sizeof( buffer ), "%Y-%m-%d %H:%M:%S", tm );

    return buffer;
}

TracyLlmTools::EmbeddingState TracyLlmTools::GetManualEmbeddingsState() const
{
    std::lock_guard lock( m_lock );
    return m_manualEmbeddingState;
}

void TracyLlmTools::SelectManualEmbeddings( const std::string& model )
{
    std::lock_guard lock( m_lock );
    assert( !m_manualEmbeddingState.inProgress );
    if( m_manualEmbeddingState.done && m_manualEmbeddingState.model == model ) return;

    auto cache = GetCachePath( model.c_str() );

    try
    {
        m_manualEmbeddings = std::make_unique<TracyLlmEmbeddings>( cache, m_manual.GetHash() );
        m_manualEmbeddingState = { .model = model, .done = true };
    }
    catch( std::exception& ) {}
}

void TracyLlmTools::BuildManualEmbeddings( const std::string& model, TracyLlmApi& api )
{
    std::unique_lock lock( m_lock );
    assert( !m_manualEmbeddingState.inProgress );
    if( m_manualEmbeddingState.done && m_manualEmbeddingState.model == model ) return;

    lock.unlock();
    if( m_thread.joinable() ) m_thread.join();

    assert( !m_cancel );
    m_manualEmbeddingState = { .model = model, .inProgress = true };
    m_thread = std::thread( [this, &api] { ManualEmbeddingsWorker( api ); } );
}

void TracyLlmTools::ManualEmbeddingsWorker( TracyLlmApi& api )
{
    auto cache = GetCachePath( m_manualEmbeddingState.model.c_str() );

    std::unique_lock lock( m_lock );
    if( m_cancel )
    {
        m_manualEmbeddingState.inProgress = false;
        m_manualEmbeddingState.done = false;
        return;
    }
    lock.unlock();

    size_t length;
    {
        nlohmann::json req;
        req["input"] = "";
        req["model"] = m_manualEmbeddingState.model;

        nlohmann::json response;
        api.Embeddings( req, response );

        length = response["data"][0]["embedding"].size();
    }

    if( length == 0 )
    {
        lock.lock();
        m_manualEmbeddingState.inProgress = false;
        return;
    }

    const auto csz = m_chunkData.size();
    m_manualEmbeddings = std::make_unique<TracyLlmEmbeddings>( length, csz );

    constexpr size_t batchSize = 4;

    std::vector<float> embeddings;
    embeddings.reserve( length );

    size_t i = 0;
    while( i < csz )
    {
        lock.lock();
        if( m_cancel )
        {
            m_manualEmbeddingState.inProgress = false;
            m_manualEmbeddingState.done = false;
            return;
        }
        m_manualEmbeddingState.progress = (float)i / csz;
        lock.unlock();

        const auto bsz = std::min( batchSize, csz - i );
        std::vector<std::string> batch;
        batch.reserve( bsz );
        for( size_t j=0; j<bsz; j++ ) batch.emplace_back( "search_document: " + m_chunkData[i+j].first );

        nlohmann::json req;
        req["input"] = std::move( batch );
        req["model"] = m_manualEmbeddingState.model;

        nlohmann::json response;
        if( !api.Embeddings( req, response ) )
        {
            m_manualEmbeddingState.inProgress = false;
            m_manualEmbeddingState.done = false;
            return;
        }

        auto& data = response["data"];
        for( size_t j=0; j<bsz; j++ )
        {
            embeddings.clear();
            for( auto& item : data[j]["embedding"] ) embeddings.emplace_back( item.get<float>() );
            m_manualEmbeddings->Add( m_chunkData[i+j].second, embeddings );
        }

        i += bsz;
    }

    m_manualEmbeddings->Save( cache, m_manual.GetHash() );

    lock.lock();
    m_manualEmbeddingState.inProgress = false;
    m_manualEmbeddingState.done = true;
}

void TracyLlmTools::CancelManualEmbeddings()
{
    if( m_thread.joinable() )
    {
        m_lock.lock();
        m_cancel = true;
        m_lock.unlock();
        m_thread.join();
        m_cancel = false;
    }
}

int TracyLlmTools::CalcMaxSize() const
{
    constexpr int limit = 32*1024;
    if( m_ctxSize <= 0 ) return limit;

    // Limit the size of the response to avoid exceeding the context size
    // Assume average token size is 4 bytes. Make space for 3 articles to be retrieved.
    const int maxSize = ( m_ctxSize * 4 ) / 3;
    return std::min( maxSize, limit );
}

std::string TracyLlmTools::TrimString( std::string&& str ) const
{
    auto maxSize = CalcMaxSize();
    if( str.size() < maxSize ) return str;

    // Check if UTF-8 continuation byte will be removed, meaning an UTF-8 character is split in the middle
    if( ( str[maxSize] & 0xC0 ) == 0xC0 )
    {
        // Remove the current UTF-8 character
        while( maxSize > 0 && ( str[maxSize-1] & 0xC0 ) == 0xC0 ) maxSize--;
        // Finally, remove the first byte of a UTF-8 multi-byte sequence
        //assert( ( str[maxSize-1] & 0xC0 ) == 0x80 );
        if( maxSize > 0 ) maxSize--;
    }
    return str.substr( 0, maxSize );
}

static size_t WriteFn( void* _data, size_t size, size_t num, void* ptr )
{
    const auto data = (unsigned char*)_data;
    const auto sz = size*num;
    auto& v = *(std::string*)ptr;
    v.append( (const char*)data, sz );
    return sz;
}

std::string TracyLlmTools::FetchWebPage( const std::string& url, bool cache )
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
    curl_easy_setopt( curl, CURLOPT_USERAGENT, s_config.llmUserAgent.c_str() );

    auto res = curl_easy_perform( curl );

    std::string response;
    if( res != CURLE_OK )
    {
        response = "Error: " + std::string( curl_easy_strerror( res ) );
    }
    else
    {
        int64_t http_code = 0;
        curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, &http_code );
        if( http_code != 200 )
        {
            response = "Error: HTTP " + std::to_string( http_code );
        }
        else
        {
            response = std::move( buf );
        }
    }
    if( cache ) m_webCache.emplace( url, response );

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
    output["preview"] = summaryJson["extract"];

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

    const auto reply = output.dump( 2, ' ', false, nlohmann::json::error_handler_t::replace );
    return { .reply = reply, .image = image };
}

std::string TracyLlmTools::GetWikipedia( std::string page, const std::string& lang )
{
    NetworkCheckString;

    std::ranges::replace( page, ' ', '_' );
    auto res = FetchWebPage( "https://" + lang + ".wikipedia.org/w/rest.php/v1/page/" + page );

    return TrimString( std::move( res ) );
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

    return TrimString( std::move( res ) );
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

    query = UrlEncode( query );

    if( !s_config.llmSearchApiKey.empty() && !s_config.llmSearchIdentifier.empty() )
    {
        const auto response = FetchWebPage( "https://customsearch.googleapis.com/customsearch/v1?key=" + s_config.llmSearchApiKey + "&cx=" + s_config.llmSearchIdentifier + "&q=" + query );
        try
        {
            auto json = nlohmann::json::parse( response );
            if( json.contains( "items" ) && json["items"].size() != 0 )
            {
                nlohmann::json results;
                for( size_t i = 0; i < json["items"].size(); i++ )
                {
                    auto& item = json["items"][i];
                    nlohmann::json result;
                    result["title"] = RemoveNewline( item["title"].get_ref<const std::string&>() );
                    result["preview"] = RemoveNewline( item["snippet"].get_ref<const std::string&>() );
                    result["url"] = RemoveNewline( item["link"].get_ref<const std::string&>() );
                    results[i] = result;
                }
                return results.dump( 2, ' ', false, nlohmann::json::error_handler_t::replace );
            }
        }
        catch( const nlohmann::json::exception& e ) {}
    }

    const auto response = FetchWebPage( "https://lite.duckduckgo.com/lite?q=" + query );

    auto doc = ParseHtml( response );
    if( !doc ) return "Error: Failed to parse HTML";

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
        result["preview"] = RemoveNewline( snippet.text().as_string() );
        result["url"] = RemoveNewline( url.text().as_string() );

        json[i] = result;
    }

    return json.dump( 2, ' ', false, nlohmann::json::error_handler_t::replace );
}

static void RemoveTag( pugi::xml_node node, const char* tag )
{
    auto nodes = node.select_nodes( tag );
    for( auto& n : nodes )
    {
        auto node = n.node();
        if( node.parent() ) node.parent().remove_child( node );
    }
}

static void RemoveAttributes( pugi::xml_node node, const char* tag, std::vector<const char*> valid = {} )
{
    auto nodes = node.select_nodes( tag );
    if( valid.empty() )
    {
        for( auto& n : nodes ) n.node().remove_attributes();
    }
    else
    {
        unordered_flat_set<std::string> toRemove;
        for( auto& n : nodes )
        {
            toRemove.clear();
            auto node = n.node();
            for( auto& attr : node.attributes() ) toRemove.emplace( attr.name() );
            for( auto& validAttr : valid )
            {
                auto it = toRemove.find( validAttr );
                if( it != toRemove.end() ) toRemove.erase( it );
            }
            for( auto& attr : toRemove )
            {
                while( node.remove_attribute( attr.c_str() ) );
            }
        }
    }
}

static void RemoveEmptyTags( pugi::xml_node node )
{
    auto child = node.first_child();
    while( child )
    {
        auto next = child.next_sibling();
        auto type = child.type();
        if( child.type() == pugi::xml_node_type::node_element )
        {
            RemoveEmptyTags( child );
            if( !child.first_child() && child.text().empty() ) { node.remove_child( child ); }
        }
        child = next;
    }
}

struct xml_writer : public pugi::xml_writer
{
    explicit xml_writer( std::string& str ) : str( str ) {}
    void write( const void* data, size_t size ) override { str.append( (const char*)data, size ); }
    std::string& str;
};

std::string TracyLlmTools::GetWebpage( const std::string& url )
{
    NetworkCheckString;

    auto data = FetchWebPage( url, false );
    auto doc = ParseHtml( data );
    if( !doc ) return "Error: Failed to parse HTML";

    auto body = doc->select_node( "/html/body" );
    if( !body ) return "Error: Failed to parse HTML";

    auto node = body.node();
    RemoveTag( node, "//script" );
    RemoveTag( node, "//style" );
    RemoveTag( node, "//link" );
    RemoveTag( node, "//meta" );
    RemoveTag( node, "//svg" );
    RemoveTag( node, "//template" );
    RemoveTag( node, "//ins" );
    RemoveAttributes( node, "//body" );
    RemoveAttributes( node, "//div" );
    RemoveAttributes( node, "//p" );
    RemoveAttributes( node, "//a", { "href", "title" } );
    RemoveAttributes( node, "//img", { "src", "alt" } );
    RemoveAttributes( node, "//li" );
    RemoveAttributes( node, "//ul", { "role" } );
    RemoveAttributes( node, "//td", { "colspan" } );
    RemoveAttributes( node, "//tr" );
    RemoveAttributes( node, "//hr" );
    RemoveAttributes( node, "//th", { "colspan", "rowspan" } );
    RemoveAttributes( node, "//table", { "role" } );
    RemoveAttributes( node, "//col" );
    RemoveAttributes( node, "//span" );
    RemoveAttributes( node, "//pre" );
    RemoveAttributes( node, "//button" );
    RemoveAttributes( node, "//label", { "title" } );
    RemoveAttributes( node, "//input", { "type", "placeholder" } );
    RemoveAttributes( node, "//form", { "action", "method" } );
    RemoveAttributes( node, "//textarea", { "placeholder" } );
    RemoveAttributes( node, "//dialog" );
    RemoveAttributes( node, "//header" );
    RemoveAttributes( node, "//footer" );
    RemoveAttributes( node, "//section" );
    RemoveAttributes( node, "//article" );
    RemoveAttributes( node, "//aside" );
    RemoveAttributes( node, "//figure" );
    RemoveAttributes( node, "//main" );
    RemoveAttributes( node, "//summary" );
    RemoveAttributes( node, "//details" );
    RemoveAttributes( node, "//nav" );
    RemoveAttributes( node, "//bdi" );
    RemoveAttributes( node, "//time", { "datetime" } );
    RemoveAttributes( node, "//h1" );
    RemoveAttributes( node, "//h2" );
    RemoveAttributes( node, "//h3" );
    RemoveAttributes( node, "//h4" );
    RemoveAttributes( node, "//h5" );
    RemoveAttributes( node, "//h6" );
    RemoveAttributes( node, "//strong" );
    RemoveAttributes( node, "//em" );
    RemoveAttributes( node, "//i" );
    RemoveAttributes( node, "//b" );
    RemoveAttributes( node, "//u" );
    RemoveEmptyTags( node );

    std::string response;
    xml_writer writer( response );
    body.node().print( writer, nullptr, pugi::format_raw | pugi::format_no_declaration | pugi::format_no_escapes );

    RemoveNewline( response );
    auto it = std::ranges::unique( response, []( char a, char b ) { return ( a == ' ' || a == '\t' ) && ( b == ' ' || b == '\t' ); } );
    response.erase( it.begin(), it.end() );

    response = TrimString( std::move( response ) );
    m_webCache.emplace( url, response );

    return response;
}

std::string TracyLlmTools::SearchManual( const std::string& query, TracyLlmApi& api, bool hasEmbeddingsModel )
{
    if( !hasEmbeddingsModel ) return "Searching the user manual requires vector embeddings model to be selected. You must inform the user that he should download such a model using their LLM provider software, so you can use this tool.";
    if( !m_manualEmbeddingState.done ) return "User manual embedding vectors are not calculated. You must inform the user that he should click the \"Learn manual\" button, so you can use this tool.";

    constexpr size_t MaxSearchResults = 20;
    constexpr size_t MaxOutputChunks = 10;

    nlohmann::json req;
    req["input"] = "search_query: " + query;
    req["model"] = m_manualEmbeddingState.model;

    nlohmann::json response;
    if( !api.Embeddings( req, response, true ) ) return "Error: Failed to get embedding for the query";
    auto& embedding = response["data"][0]["embedding"];

    if( embedding.empty() ) return "Error: Failed to get embedding for the query";

    std::vector<float> vec;
    vec.reserve( embedding.size() );
    for( auto& item : embedding ) vec.emplace_back( item.get<float>() );

    auto results = m_manualEmbeddings->Search( vec, MaxSearchResults );
    std::ranges::sort( results, []( const auto& a, const auto& b ) { return a.distance < b.distance; } );

    std::vector<std::pair<int, float>> chunks;
    chunks.reserve( results.size() );
    for( auto& item : results )
    {
        const auto chunk = m_manualEmbeddings->Get( item.idx );
        if( std::ranges::find_if( chunks, [chunk]( const auto& v ) { return v.first == chunk; } ) == chunks.end() ) chunks.emplace_back( chunk, item.distance );
    }
    if( chunks.size() > MaxOutputChunks ) chunks.resize( MaxOutputChunks );

    auto& manualChunks = m_manual.GetChunks();
    const auto maxSize = CalcMaxSize();
    int totalSize = 0;
    int idx;
    for( idx = 0; idx < chunks.size(); idx++ )
    {
        totalSize += manualChunks[chunks[idx].first].text.size();
        if( totalSize >= maxSize ) break;
    }
    if( idx < chunks.size() ) chunks.resize( idx );

    nlohmann::json json;
    for( auto& chunk : chunks )
    {
        auto& m = manualChunks[chunk.first];
        nlohmann::json r;
        r["distance"] = chunk.second;
        r["content"] = m.text;
        r["section"] = m.section;
        r["title"] = m.title;
        r["parents"] = m.parents;
        json.emplace_back( std::move( r ) );
    }

    return json.dump( 2, ' ', false, nlohmann::json::error_handler_t::replace );
}

std::string TracyLlmTools::SourceFile( const std::string& file, uint32_t line, uint32_t context ) const
{
    if( line == 0 ) return "Error: Source file line number must be greater than 0.";

    const auto data = m_worker.GetSourceFileFromCache( file.c_str() );
    if( data.data == nullptr ) return "Error: Source file not available.";

    auto lines = SplitLines( data.data, data.len );
    if( line > lines.size() ) return "Error: Source file line " + std::to_string( line ) + " is out of range. The file has only " + std::to_string( lines.size() ) + " lines.";

    line--;

    const auto maxSize = CalcMaxSize();
    int size = lines[line].size() + 1;
    uint32_t minLine = line;
    uint32_t maxLine = line+1;

    while( context > 0 && ( minLine > 0 || maxLine < lines.size() ) )
    {
        if( minLine > 0 )
        {
            size += lines[minLine].size() * 3 + 30;
            if( size >= maxSize ) break;
            minLine--;
        }
        if( maxLine < lines.size() )
        {
            size += lines[maxLine].size() * 3 + 30;
            if( size >= maxSize ) break;
            maxLine++;
        }
        context--;
    }

    nlohmann::json json = {
        { "file", file },
        { "contents", nlohmann::json::array() }
    };

    for( uint32_t i = minLine; i < maxLine; i++ )
    {
        nlohmann::json lineJson = {
            { "line", i + 1 },
            { "text", lines[i] }
        };
        json["contents"].emplace_back( std::move( lineJson ) );
    }

    return json.dump( 2, ' ', false, nlohmann::json::error_handler_t::replace );
}

std::string TracyLlmTools::SourceSearch( std::string query, bool caseInsensitive ) const
{
    auto& cache = m_worker.GetSourceFileCache();
    nlohmann::json json = {};

    size_t total = 0;
    for( auto& item : cache )
    {
        if( IsFrameExternal( item.first, nullptr ) ) continue;

        char* tmp = nullptr;
        auto& mem = item.second;
        auto start = mem.data;
        auto end = start + mem.len;

        if( caseInsensitive )
        {
            tmp = new char[mem.len];
            std::transform( start, end, tmp, []( char c ) { return std::tolower( c ); } );
            start = tmp;
            end = tmp + mem.len;
            std::transform( query.begin(), query.end(), query.begin(), []( char c ) { return std::tolower( c ); } );
        }

        if( std::search( start, end, query.begin(), query.end() ) == end )
        {
            delete[] tmp;
            continue;
        }

        std::vector<size_t> res;
        auto lines = SplitLines( start, mem.len );
        for( size_t idx = 0; idx < lines.size(); idx++ )
        {
            if( lines[idx].find( query ) != std::string::npos )
            {
                res.emplace_back( idx );
                total++;
            }
        }
        assert( !res.empty() );

        auto r = nlohmann::json::array();
        if( caseInsensitive )
        {
            auto linesOrig = SplitLines( mem.data, mem.len );
            for( auto& line : res )
            {
                r.push_back( {
                    { "line", line + 1 },
                    { "text", linesOrig[line] }
                } );
            }
        }
        else
        {
            for( auto& line : res )
            {
                r.push_back( {
                    { "line", line + 1 },
                    { "text", lines[line] }
                } );
            }
        }

        json.push_back( {
            { "file", item.first },
            { "matches", std::move( r ) }
        } );

        delete[] tmp;
    }

    if( total == 0 ) return "No matches found.";
    auto ret = json.dump( 2, ' ', false, nlohmann::json::error_handler_t::replace );
    if( ret.size() > CalcMaxSize() ) return "Too many matches found.";
    return ret;
}

}
