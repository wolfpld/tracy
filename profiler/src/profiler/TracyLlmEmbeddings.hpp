#ifndef __TRACYLLMEMBEDDINGS_HPP__
#define __TRACYLLMEMBEDDINGS_HPP__

#include <stddef.h>
#include <usearch/index_dense.hpp>
#include <vector>

namespace tracy
{

class TracyLlmEmbeddings
{
public:
    struct Result
    {
        size_t idx;
        float distance;
    };

    explicit TracyLlmEmbeddings( size_t length, size_t reserve = 0 );
    explicit TracyLlmEmbeddings( const char* file, uint64_t hash );

    void Add( uint32_t idx, const std::vector<float>& embedding );
    [[nodiscard]] std::vector<Result> Search( const std::vector<float>& embedding, size_t k ) const;
    [[nodiscard]] uint32_t Get( size_t idx ) const { return m_data[idx]; }

    bool Save( const char* file, uint64_t hash ) const;

private:
    unum::usearch::index_dense_t m_index;
    std::vector<uint32_t> m_data;
};

}

#endif
