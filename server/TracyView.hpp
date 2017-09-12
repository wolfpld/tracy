#ifndef __TRACYVIEW_HPP__
#define __TRACYVIEW_HPP__

#include <atomic>
#include <string>
#include <thread>

namespace tracy
{

class View
{
public:
    View() : View( "127.0.0.1" ) {}
    View( const char* addr );
    ~View();

private:
    void Worker();

    std::string m_addr;

    std::thread m_thread;
    std::atomic<bool> m_shutdown;
};

}

#endif
