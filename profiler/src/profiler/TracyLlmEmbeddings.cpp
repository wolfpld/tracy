#include "TracyLlmEmbeddings.hpp"

namespace tracy
{

TracyLlmEmbeddings::TracyLlmEmbeddings( size_t length, size_t reserve )
{
    unum::usearch::metric_punned_t metric( length );
    m_index = unum::usearch::index_dense_t::make( metric );
    if( reserve > 0 ) m_index.reserve( reserve );
}

void TracyLlmEmbeddings::Add( int idx, const std::vector<float>& embedding )
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

}
