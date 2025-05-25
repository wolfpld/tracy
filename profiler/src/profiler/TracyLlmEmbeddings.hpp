#ifndef __TRACYLLMEMBEDDINGS_HPP__
#define __TRACYLLMEMBEDDINGS_HPP__

#include <stddef.h>
#include <string>
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

    struct Chunk
    {
        const char* str;
        size_t length;
    };

    explicit TracyLlmEmbeddings( size_t length, size_t reserve = 0 );

    void Add( const char* chunk, size_t chunkLen, const std::vector<float>& embedding );
    [[nodiscard]] std::vector<Result> Search( const std::vector<float>& embedding, size_t k ) const;
    [[nodiscard]] const Chunk& Get( size_t idx ) const { return m_data[idx]; }

private:
    unum::usearch::index_dense_t m_index;
    std::vector<Chunk> m_data;
};

}

#endif
