#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "ConnectionHistory.hpp"

#include "../../server/tracy_pdqsort.h"
#include "profiler/TracyStorage.hpp"


ConnectionHistory::ConnectionHistory()
    : m_fn( tracy::GetSavePath( "connection.history" ) )
{
    FILE* f = fopen( m_fn.c_str(), "rb" );
    if( !f ) return;

    uint64_t sz;
    if( fread( &sz, 1, sizeof( sz ), f ) != sizeof( sz ) ) goto err;
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ssz, cnt;
        if( fread( &ssz, 1, sizeof( ssz ), f ) != sizeof( ssz ) ) goto err;
        if( ssz >= 1024 ) goto err;
        char tmp[1024];
        if( fread( tmp, 1, ssz, f ) != ssz ) goto err;
        if( fread( &cnt, 1, sizeof( cnt ), f ) != sizeof( cnt ) ) goto err;
        m_connHistMap.emplace( std::string( tmp, tmp+ssz ), cnt );
    }
    fclose( f );

    Rebuild();
    return;

err:
    fclose( f );
    m_connHistMap.clear();
}

ConnectionHistory::~ConnectionHistory()
{
    FILE* f = fopen( m_fn.c_str(), "wb" );
    if( !f ) return;

    uint64_t sz = uint64_t( m_connHistMap.size() );
    fwrite( &sz, 1, sizeof( uint64_t ), f );
    for( auto& v : m_connHistMap )
    {
        sz = uint64_t( v.first.size() );
        fwrite( &sz, 1, sizeof( uint64_t ), f );
        fwrite( v.first.c_str(), 1, sz, f );
        fwrite( &v.second, 1, sizeof( v.second ), f );
    }
    fclose( f );
}

void ConnectionHistory::Rebuild()
{
    std::vector<std::unordered_map<std::string, uint64_t>::const_iterator> vec;
    vec.reserve( m_connHistMap.size() );
    for( auto it = m_connHistMap.begin(); it != m_connHistMap.end(); ++it )
    {
        vec.emplace_back( it );
    }
    tracy::pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second > rhs->second; } );
    std::swap( m_connHistVec, vec );
}

void ConnectionHistory::Count( const char* name )
{
    std::string addr( name );
    auto it = m_connHistMap.find( addr );
    if( it != m_connHistMap.end() )
    {
        it->second++;
    }
    else
    {
        m_connHistMap.emplace( std::move( addr ), 1 );
    }
    Rebuild();
}

void ConnectionHistory::Erase( size_t idx )
{
    assert( idx < m_connHistVec.size() );
    m_connHistMap.erase( m_connHistVec[idx] );
    Rebuild();
}
