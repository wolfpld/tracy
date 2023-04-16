#include "RunQueue.hpp"

RunQueue::RunQueue()
    : m_mainThread( std::this_thread::get_id() )
{
}

void RunQueue::Queue( const std::function<void()>& cb, bool forceDelay )
{
    if( !forceDelay && std::this_thread::get_id() == m_mainThread )
    {
        cb();
    }
    else
    {
        std::lock_guard<std::mutex> lock( m_lock );
        m_queue.emplace_back( cb );
    }
}

void RunQueue::Run()
{
    std::unique_lock<std::mutex> lock( m_lock );
    if( !m_queue.empty() )
    {
        std::vector<std::function<void()>> tmp;
        std::swap( tmp, m_queue );
        lock.unlock();
        for( auto& cb : tmp ) cb();
    }
}
