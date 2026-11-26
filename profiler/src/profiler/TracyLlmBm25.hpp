#ifndef __TRACYLLMBM25_HPP__
#define __TRACYLLMBM25_HPP__

#include <stdint.h>
#include <string>
#include <string_view>
#include <vector>

#include "tracy_robin_hood.h"

namespace tracy
{

class TracyLlmBm25
{
public:
    struct Doc
    {
        std::string header;
        std::string_view text;
    };

    struct Result
    {
        uint32_t doc;
        float score;
    };

    explicit TracyLlmBm25( std::vector<Doc>&& docs );

    [[nodiscard]] std::vector<Result> Search( const std::string& query, size_t k ) const;

private:
    struct Posting
    {
        uint32_t doc;
        std::vector<int32_t> positions;
    };

    static void Tokenize( std::string_view text, std::vector<std::string>& out );

    unordered_flat_map<std::string, std::vector<Posting>> m_postings;
    unordered_flat_map<std::string, uint32_t> m_df;
    std::vector<std::string> m_vocab;
    std::vector<int32_t> m_docLen;
    double m_avgdl = 0;
    int m_numDocs = 0;
};

}

#endif
