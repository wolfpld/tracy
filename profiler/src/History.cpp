#include <algorithm>
#include <assert.h>
#include <filesystem>
#include <stdio.h>

#include <nlohmann/json.hpp>

#include "History.hpp"

#include "../../server/tracy_pdqsort.h"
#include "profiler/TracyStorage.hpp"

static constexpr size_t RecentTracesMax = 10;

History::History()
    : m_fn( tracy::GetSavePath( "history.json" ) )
{
    Load();
}

History::~History()
{
    Save();
}

void History::Load()
{
    FILE* f = fopen( m_fn.c_str(), "rb" );
    if( !f ) return;

    try
    {
        const auto json = nlohmann::json::parse( f );

        if( json.contains( "connections" ) && json["connections"].is_array() )
        {
            for( auto& v : json["connections"] )
            {
                if( !v.is_object() || !v.contains( "address" ) || !v["address"].is_string() ) continue;
                auto address = v["address"].get<std::string>();
                // The welcome window copies the address into a 1024 bytes buffer and treats it as a C string.
                if( address.empty() || address.size() >= 1024 || address.find( '\0' ) != std::string::npos ) continue;
                const uint64_t count = v.contains( "count" ) && v["count"].is_number_unsigned() ? v["count"].get<uint64_t>() : 1;
                // A hand-edited file may list the same address twice.
                const auto [it, inserted] = m_connectionsMap.try_emplace( std::move( address ), count );
                if( !inserted ) it->second += std::min( count, UINT64_MAX - it->second );
            }
        }

        if( json.contains( "recentTraces" ) && json["recentTraces"].is_array() )
        {
            for( auto& v : json["recentTraces"] )
            {
                if( !v.is_string() ) continue;
                auto path = v.get<std::string>();
                if( path.empty() || path.find( '\0' ) != std::string::npos || std::find( m_recentTraces.begin(), m_recentTraces.end(), path ) != m_recentTraces.end() ) continue;
                m_recentTraces.push_back( std::move( path ) );
                if( m_recentTraces.size() == RecentTracesMax ) break;
            }
        }
    }
    catch( nlohmann::json::exception& )
    {
    }

    fclose( f );

    Rebuild();
}

void History::Save() const
{
    auto connections = nlohmann::json::array();
    for( const auto& c : m_connectionsVec ) connections.push_back( { { "address", c->first }, { "count", c->second } } );

    const nlohmann::json j = { { "connections", connections }, { "recentTraces", m_recentTraces } };
    const auto data = j.dump( 2, ' ', false, nlohmann::json::error_handler_t::replace );

    FILE* f = fopen( m_fn.c_str(), "wb" );
    if( !f ) return;
    fwrite( data.c_str(), 1, data.size(), f );
    fclose( f );
}

void History::Rebuild()
{
    std::vector<std::unordered_map<std::string, uint64_t>::const_iterator> vec;
    vec.reserve( m_connectionsMap.size() );
    for( auto it = m_connectionsMap.begin(); it != m_connectionsMap.end(); ++it )
    {
        vec.emplace_back( it );
    }
    tracy::pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second > rhs->second; } );
    std::swap( m_connectionsVec, vec );
}

void History::CountConnection( const std::string& address )
{
    auto it = m_connectionsMap.find( address );
    if( it != m_connectionsMap.end() )
    {
        it->second++;
    }
    else
    {
        m_connectionsMap.emplace( address, 1 );
    }
    Rebuild();
}

void History::EraseConnection( size_t idx )
{
    assert( idx < m_connectionsVec.size() );
    m_connectionsMap.erase( m_connectionsVec[idx] );
    Rebuild();
}

void History::RecordTrace( const char* path )
{
    std::error_code ec;
    auto abs = std::filesystem::absolute( std::filesystem::path( path ), ec ).lexically_normal().string();
    if( ec ) abs = path;
    m_recentTraces.erase( std::remove( m_recentTraces.begin(), m_recentTraces.end(), abs ), m_recentTraces.end() );
    m_recentTraces.insert( m_recentTraces.begin(), std::move( abs ) );
    if( m_recentTraces.size() > RecentTracesMax ) m_recentTraces.resize( RecentTracesMax );
}
