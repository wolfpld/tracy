#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "ConnectionHistory.hpp"

#include "../../server/tracy_pdqsort.h"
#include "../../server/TracyStorage.hpp"


ConnectionHistory::ConnectionHistory()
    : m_fn( tracy::GetSavePath( "connection.history" ) )
{
    FILE* f = fopen( m_fn.c_str(), "rb" );
    if( !f ) return;

    uint64_t sz;
    fread( &sz, 1, sizeof( sz ), f );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ssz, cnt;
        fread( &ssz, 1, sizeof( ssz ), f );
        assert( ssz < 1024 );
        char tmp[1024];
        fread( tmp, 1, ssz, f );
        fread( &cnt, 1, sizeof( cnt ), f );
        m_connHistMap.emplace( std::string( tmp, tmp+ssz ), cnt );
    }
    fclose( f );

    Rebuild();
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
