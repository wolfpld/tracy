#ifndef __TRACYMARKDOWN_HPP__
#define __TRACYMARKDOWN_HPP__

#include <stddef.h>

struct MD_PARSER;

namespace tracy
{

class View;
class Worker;

class Markdown
{
public:
    Markdown( View* view, Worker* worker );
    ~Markdown();

    void Print( const char* str, size_t size );

private:
    MD_PARSER* m_parser;
    View* m_view;
    Worker* m_worker;
};

}

#endif
