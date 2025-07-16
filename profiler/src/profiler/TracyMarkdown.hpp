#ifndef __TRACYMARKDOWN_HPP__
#define __TRACYMARKDOWN_HPP__

#include <stddef.h>

struct MD_PARSER;

namespace tracy
{

class Markdown
{
public:
    Markdown();
    ~Markdown();

    void Print( const char* str, size_t size );

private:
    MD_PARSER* m_parser;
};

}

#endif
