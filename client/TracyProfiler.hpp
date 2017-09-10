#ifndef __TRACYPROFILER_HPP__
#define __TRACYPROFILER_HPP__

#include <atomic>
#include <thread>

namespace tracy
{

class Profiler
{
public:
    Profiler();
    ~Profiler();

private:
    void Worker();

    std::thread m_thread;
    std::atomic<bool> m_shutdown;
};

};

#endif
