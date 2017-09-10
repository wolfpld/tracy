#ifndef __TRACYPROFILER_HPP__
#define __TRACYPROFILER_HPP__

#include <atomic>
#include <stdint.h>
#include <thread>

namespace tracy
{

class Profiler
{
public:
    Profiler();
    ~Profiler();

    static uint64_t GetNewId();

private:
    void Worker();

    std::thread m_thread;
    std::atomic<bool> m_shutdown;
    std::atomic<uint64_t> m_id;
};

};

#endif
