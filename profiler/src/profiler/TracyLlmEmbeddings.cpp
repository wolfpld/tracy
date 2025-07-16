#ifdef _WIN32
#  include <windows.h>
#  include <io.h>
#else
#  include <unistd.h>
#endif

#include "TracyLlmEmbeddings.hpp"

namespace tracy
{

TracyLlmEmbeddings::TracyLlmEmbeddings( size_t length, size_t reserve )
{
    unum::usearch::metric_punned_t metric( length );
    m_index = unum::usearch::index_dense_t::make( metric );
    if( reserve > 0 ) m_index.reserve( reserve );
}

TracyLlmEmbeddings::TracyLlmEmbeddings( const char* file, uint64_t hash )
{
    FILE* f = fopen( file, "rb" );
    if( !f ) throw std::runtime_error( "Failed to open embeddings file: " + std::string( file ) );

    uint64_t fileHash, size;
    if( fread( &fileHash, 1, sizeof( fileHash ), f ) != sizeof( fileHash ) ||
        fread( &size, 1, sizeof( size ), f ) != sizeof( size ) )
    {
        fclose( f );
        throw std::runtime_error( "Failed to read embeddings file: " + std::string( file ) );
    }

    if( fileHash != hash )
    {
        fclose( f );
        throw std::runtime_error( "Embeddings file hash mismatch: " + std::string( file ) );
    }

    m_data.resize( size );
    auto loaded = fread( m_data.data(), 1, m_data.size() * sizeof( uint32_t ), f ) == m_data.size() * sizeof( uint32_t );
    fclose( f );
    if( !loaded ) throw std::runtime_error( "Failed to read embeddings data from file: " + std::string( file ) );

    const auto dbPath = file + std::string( ".db" );
    unum::usearch::index_dense_t index;
    auto res = index.view( dbPath.c_str() );
    if( !res ) throw std::runtime_error( "Failed to load embeddings database from file: " + std::string( file ) );
    m_index = std::move( index );
}

void TracyLlmEmbeddings::Add( uint32_t idx, const std::vector<float>& embedding )
{
    m_index.add( m_data.size(), embedding.data() );
    m_data.emplace_back( idx );
}

std::vector<TracyLlmEmbeddings::Result> TracyLlmEmbeddings::Search( const std::vector<float>& embedding, size_t k ) const
{
    std::vector<Result> ret;
    auto result = m_index.search( embedding.data(), k );
    ret.reserve( result.size() );
    for( size_t i=0; i<result.size(); i++ )
    {
        ret.emplace_back( Result {
            .idx = result[i].member.key,
            .distance = result[i].distance
        } );
    }
    return ret;
}

bool TracyLlmEmbeddings::Save( const char* file, uint64_t hash ) const
{
    const auto dbPath = file + std::string( ".db" );
    if( !m_index.save( dbPath.c_str() ) ) return false;

    FILE* f = fopen( file, "wb" );
    if( !f )
    {
        unlink( dbPath.c_str() );
        return false;
    }

    const uint64_t size = m_data.size();

    if( fwrite( &hash, 1, sizeof( hash ), f ) != sizeof( hash ) ||
        fwrite( &size, 1, sizeof( size ), f ) != sizeof( size ) ||
        fwrite( m_data.data(), 1, m_data.size() * sizeof( uint32_t ), f ) != m_data.size() * sizeof( uint32_t ) )
    {
        fclose( f );
        unlink( dbPath.c_str() );
        unlink( file );
        return false;
    }

    fclose( f );
    return true;
}

}
