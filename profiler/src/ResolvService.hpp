#ifndef __RESOLVSERVICE_HPP__
#define __RESOLVSERVICE_HPP__

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <stdint.h>
#include <string>
#include <thread>
#include <vector>

class ResolvService
{
    struct QueueItem
    {
        uint32_t ip;
        std::function<void(std::string&&)> callback;
    };

public:
    ResolvService( uint16_t port );
    ~ResolvService();

    void Query( uint32_t ip, const std::function<void(std::string&&)>& callback );

private:
    void Worker();

    std::atomic<bool> m_exit;
    std::mutex m_lock;
    std::condition_variable m_cv;
    std::vector<QueueItem> m_queue;
    uint16_t m_port;
    std::thread m_thread;
};

#endif
