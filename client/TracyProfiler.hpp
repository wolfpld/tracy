#ifndef __TRACYPROFILER_HPP__
#define __TRACYPROFILER_HPP__

#include <atomic>
#include <stdint.h>
#include <thread>

#include "concurrentqueue.h"
#include "TracyQueue.hpp"

namespace tracy
{

class Profiler
{
public:
    Profiler();
    ~Profiler();

    static uint64_t GetNewId();

    static void ZoneBegin( QueueZoneBegin&& data );
    static void ZoneEnd( QueueZoneEnd&& data );

private:
    void Worker();

    int64_t m_timeBegin;
    std::thread m_thread;
    std::atomic<bool> m_shutdown;
    moodycamel::ConcurrentQueue<QueueItem> m_queue;
    std::atomic<uint64_t> m_id;
};

};

#endif
