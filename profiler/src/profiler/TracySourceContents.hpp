#ifndef __TRACYSOURCECONTENTS_HPP__
#define __TRACYSOURCECONTENTS_HPP__

#include <stdint.h>
#include <stddef.h>
#include <vector>

#include "TracySourceTokenizer.hpp"

namespace tracy
{

class View;
class Worker;

class SourceContents
{
public:
    SourceContents();
    ~SourceContents();

    void Parse( const char* fileName, const Worker& worker, const View& view );
    void Parse( const char* source );

    const std::vector<Tokenizer::Line>& get() const { return m_lines; }
    bool empty() const { return m_lines.empty(); }

    const char* filename() const { return m_file; }
    uint32_t idx() const { return m_fileStringIdx; }
    bool is_cached() const { return m_data != m_dataBuf; }
    const char* data() const { return m_data; }
    size_t data_size() const { return m_dataSize; }

private:
    void Tokenize( const char* txt, size_t sz );

    const char* m_file;
    uint32_t m_fileStringIdx;

    const char* m_data;
    char* m_dataBuf;
    size_t m_dataSize;

    std::vector<Tokenizer::Line> m_lines;
};

}

#endif
