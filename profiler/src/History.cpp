#include <algorithm>
#include <assert.h>
#include <stdio.h>

#include <nlohmann/json.hpp>

#include "History.hpp"

#include "../../server/tracy_pdqsort.h"
#include "profiler/TracyStorage.hpp"

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

    const nlohmann::json j = { { "connections", connections } };
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
