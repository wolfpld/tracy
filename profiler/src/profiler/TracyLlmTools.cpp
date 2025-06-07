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
#include "TracyEmbed.hpp"
#include "TracyLlmApi.hpp"
#include "TracyLlmTools.hpp"
#include "TracyStorage.hpp"
#include "tracy_xxhash.h"

#include "data/Manual.hpp"

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

TracyLlmTools::TracyLlmTools()
    : m_manual( Unembed( Manual ) )
{
    std::string_view manual( m_manual->data(), m_manual->size() );
    const auto sz = (int)m_manual->size();

    std::vector<int> levels = { 0 };
    std::vector<std::string> chapterNames = { "Title Page" };

    int manualChunkPos = 0;
    int pos = 0;
    while( pos < sz )
    {
        auto next = manual.find( '\n', pos );
        if( next == std::string_view::npos ) next = sz;
        if( next != pos )
        {
            std::string_view line( manual.data() + pos, next - pos );
            if( line[0] == '#' )
            {
                if( manualChunkPos != pos )
                {
                    std::string manualChunk;
                    if( levels[0] != 0 )
                    {
                        manualChunk += "Section " + std::to_string( levels[0] );
                        for( size_t i=1; i<levels.size(); i++ ) manualChunk += "." + std::to_string( levels[i] );
                        manualChunk += "\n";
                    }
                    manualChunk += "Navigation: " + chapterNames[0];
                    for( size_t i=1; i<levels.size(); i++ ) manualChunk += " > " + chapterNames[i];
                    manualChunk += "\n\n";
                    manualChunk += std::string( manual.data() + manualChunkPos, pos - manualChunkPos );
                    m_manualChunks.emplace_back( std::move( manualChunk ) );
                    manualChunkPos = pos;
                }

                int level = 1;
                if( line.find( ".unnumbered}" ) == std::string_view::npos )
                {
                    while( level < line.size() && line[level] == '#' ) level++;
                    if( level != levels.size() )
                    {
                        levels.resize( level, 0 );
                        chapterNames.resize( level );
                    }
                    levels[level - 1]++;
                    chapterNames[level - 1] = line.substr( level + 1 );
                }
            }
            else
            {
                std::string chunk;
                if( levels[0] != 0 )
                {
                    chunk += "Section " + std::to_string( levels[0] );
                    for( size_t i=1; i<levels.size(); i++ ) chunk += "." + std::to_string( levels[i] );
                    chunk += "\n";
                }
                chunk += chapterNames[levels.size()-1] + "\n\n";
                chunk += std::string( line );
                m_chunkData.emplace_back( std::move( chunk ), m_manualChunks.size() );
            }
        }
        pos = next + 1;
    }
    if( manualChunkPos != pos )
    {
        std::string manualChunk;
        if( levels[0] != 0 )
        {
            manualChunk += "Section " + std::to_string( levels[0] );
            for( size_t i=1; i<levels.size(); i++ ) manualChunk += "." + std::to_string( levels[i] );
            manualChunk += "\n";
        }
        manualChunk += "Navigation: " + chapterNames[0];
        for( size_t i=1; i<levels.size(); i++ ) manualChunk += " > " + chapterNames[i];
        manualChunk += "\n\n";
        manualChunk += std::string( manual.data() + manualChunkPos, pos - manualChunkPos );
        m_manualChunks.emplace_back( std::move( manualChunk ) );
    }
}

TracyLlmTools::~TracyLlmTools()
{
    CancelManualEmbeddings();
}

TracyLlmTools::ToolReply TracyLlmTools::HandleToolCalls( const std::string& name, const std::vector<std::string>& args, TracyLlmApi& api, int contextSize, bool hasEmbeddingsModel )
{
    m_ctxSize = contextSize;

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
    if( name == "get_webpage" )
    {
        if( args.empty() ) return { .reply = "Missing URL argument" };
        return { .reply = GetWebpage( args[0] ) };
    }
    if( name == "user_manual" )
    {
        if( args.empty() ) return { .reply = "Missing search term argument" };
        return { .reply = SearchManual( args[0], api, hasEmbeddingsModel ) };
    }
    return { .reply = "Unknown tool call: " + name };
}

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

    const uint64_t hash = XXH3_64bits( m_manual->data(), m_manual->size() );
    auto cache = GetCachePath( model.c_str() );

    try
    {
        m_manualEmbeddings = std::make_unique<TracyLlmEmbeddings>( cache, hash );
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
    const uint64_t hash = XXH3_64bits( m_manual->data(), m_manual->size() );
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

    constexpr size_t batchSize = 64;

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
        for( size_t j=0; j<bsz; j++ ) batch.emplace_back( m_chunkData[i+j].first );

        nlohmann::json req;
        req["input"] = std::move( batch );
        req["model"] = m_manualEmbeddingState.model;

        nlohmann::json response;
        api.Embeddings( req, response );

        auto& data = response["data"];
        for( size_t j=0; j<bsz; j++ )
        {
            embeddings.clear();
            for( auto& item : data[j]["embedding"] ) embeddings.emplace_back( item.get<float>() );
            m_manualEmbeddings->Add( m_chunkData[i+j].second, embeddings );
        }

        i += bsz;
    }

    m_manualEmbeddings->Save( cache, hash );

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
    if( m_ctxSize <= 0 ) return 32*1024;

    // Limit the size of the response to avoid exceeding the context size
    // Assume average token size is 4 bytes. Make space for 3 articles to be retrieved.
    const auto maxSize = ( m_ctxSize * 4 ) / 3;
    return maxSize;
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

    std::ranges::replace( query, ' ', '+' );
    const auto response = FetchWebPage( "https://lite.duckduckgo.com/lite?q=" + UrlEncode( query ) );

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
        result["snippet"] = RemoveNewline( snippet.text().as_string() );
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

    std::string response;

    if( !s_config.llmReadability.empty() )
    {
        auto curl = curl_easy_init();
        if( !curl ) return "Error: Failed to initialize cURL";

        nlohmann::json post;
        post["url"] = url;
        auto postStr = post.dump( -1, ' ', false, nlohmann::json::error_handler_t::replace );

        std::string buf;

        curl_slist *hdr = nullptr;
        hdr = curl_slist_append( hdr, "Accept: application/json" );
        hdr = curl_slist_append( hdr, "Content-Type: application/json" );

        curl_easy_setopt( curl, CURLOPT_NOSIGNAL, 1L );
        curl_easy_setopt( curl, CURLOPT_URL, "http://localhost:3000/" );
        curl_easy_setopt( curl, CURLOPT_HTTPHEADER, hdr );
        curl_easy_setopt( curl, CURLOPT_CA_CACHE_TIMEOUT, 604800L );
        curl_easy_setopt( curl, CURLOPT_FOLLOWLOCATION, 1L );
        curl_easy_setopt( curl, CURLOPT_TIMEOUT, 120 );
        curl_easy_setopt( curl, CURLOPT_POSTFIELDS, postStr.c_str() );
        curl_easy_setopt( curl, CURLOPT_POSTFIELDSIZE, postStr.size() );
        curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, WriteFn );
        curl_easy_setopt( curl, CURLOPT_WRITEDATA, &buf );
        curl_easy_setopt( curl, CURLOPT_USERAGENT, s_config.llmUserAgent.c_str() );

        auto res = curl_easy_perform( curl );
        curl_slist_free_all( hdr );

        if( res == CURLE_OK )
        {
            try
            {
                auto json = nlohmann::json::parse( buf );
                if( json.contains( "content" ) ) response = json["content"].get_ref<const std::string&>();
            }
            catch( const nlohmann::json::exception& e ) {}
        }
        curl_easy_cleanup( curl );
    }

    if( response.empty() )
    {
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

        xml_writer writer( response );
        body.node().print( writer, nullptr, pugi::format_raw | pugi::format_no_declaration | pugi::format_no_escapes );

        RemoveNewline( response );
        auto it = std::ranges::unique( response, []( char a, char b ) { return ( a == ' ' || a == '\t' ) && ( b == ' ' || b == '\t' ); } );
        response.erase( it.begin(), it.end() );
    }
    response = TrimString( std::move( response ) );
    m_webCache.emplace( url, response );
    return response;
}

std::string TracyLlmTools::SearchManual( const std::string& query, TracyLlmApi& api, bool hasEmbeddingsModel )
{
    if( !hasEmbeddingsModel ) return "Searching the user manual requires vector embeddings model to be selected. You must inform the user that he should download such a model using their LLM provider software, so you can use this tool.";
    if( !m_manualEmbeddingState.done ) return "User manual embedding vectors are not calculated. You must inform the user that he should click the \"Learn manual\" button, so you can use this tool.";

    nlohmann::json req;
    req["input"] = query;
    req["model"] = m_manualEmbeddingState.model;

    nlohmann::json response;
    api.Embeddings( req, response, true );
    auto& embedding = response["data"][0]["embedding"];
    std::vector<float> vec;
    vec.reserve( embedding.size() );
    for( auto& item : embedding ) vec.emplace_back( item.get<float>() );

    auto results = m_manualEmbeddings->Search( vec, 10 );
    std::ranges::sort( results, []( const auto& a, const auto& b ) { return a.distance < b.distance; } );

    std::vector<std::pair<int, float>> chunks;
    chunks.reserve( results.size() );
    for( auto& item : results )
    {
        const auto chunk = m_manualEmbeddings->Get( item.idx );
        if( std::ranges::find_if( chunks, [chunk]( const auto& v ) { return v.first == chunk; } ) == chunks.end() ) chunks.emplace_back( chunk, item.distance );
    }
    if( chunks.size() > 5 ) chunks.resize( 5 );

    const auto maxSize = CalcMaxSize();
    int totalSize = 0;
    int idx;
    for( idx = 0; idx < chunks.size(); idx++ )
    {
        totalSize += m_manualChunks[chunks[idx].first].size();
        if( totalSize >= maxSize ) break;
    }
    if( idx < chunks.size() ) chunks.resize( idx );

    nlohmann::json json;
    for( auto& chunk : chunks )
    {
        nlohmann::json r;
        r["distance"] = chunk.second;
        r["text"] = m_manualChunks[chunk.first];
        json.emplace_back( std::move( r ) );
    }

    return json.dump( 2, ' ', false, nlohmann::json::error_handler_t::replace );
}

}
