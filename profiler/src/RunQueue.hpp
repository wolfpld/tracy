#ifndef __RUNQUEUE_HPP__
#define __RUNQUEUE_HPP__

#include <functional>
#include <mutex>
#include <thread>
#include <vector>

class RunQueue
{
public:
    RunQueue();

    void Queue( const std::function<void()>& cb, bool forceDelay = false );
    void Run();

private:
    std::vector<std::function<void()>> m_queue;
    std::mutex m_lock;
    std::thread::id m_mainThread;
};

#endif
