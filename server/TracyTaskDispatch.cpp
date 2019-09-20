#include <assert.h>
#include <stdio.h>

#include "TracyTaskDispatch.hpp"

namespace tracy
{

TaskDispatch::TaskDispatch( size_t workers )
    : m_exit( false )
    , m_jobs( 0 )
{
    assert( workers >= 1 );

    m_workers.reserve( workers );
    for( size_t i=0; i<workers; i++ )
    {
        m_workers.emplace_back( std::thread( [this]{ Worker(); } ) );
    }
}

TaskDispatch::~TaskDispatch()
{
    m_exit.store( true, std::memory_order_release );
    m_queueLock.lock();
    m_cvWork.notify_all();
    m_queueLock.unlock();

    for( auto& worker : m_workers )
    {
        worker.join();
    }
}

void TaskDispatch::Queue( const std::function<void(void)>& f )
{
    std::lock_guard<std::mutex> lock( m_queueLock );
    m_queue.emplace_back( f );
    m_cvWork.notify_one();
}

void TaskDispatch::Queue( std::function<void(void)>&& f )
{
    std::lock_guard<std::mutex> lock( m_queueLock );
    m_queue.emplace_back( std::move( f ) );
    m_cvWork.notify_one();
}

void TaskDispatch::Sync()
{
    std::unique_lock<std::mutex> lock( m_queueLock );
    while( !m_queue.empty() )
    {
        auto f = m_queue.back();
        m_queue.pop_back();
        lock.unlock();
        f();
        lock.lock();
    }
    m_cvJobs.wait( lock, [this]{ return m_jobs == 0; } );
}

void TaskDispatch::Worker()
{
    for(;;)
    {
        std::unique_lock<std::mutex> lock( m_queueLock );
        m_cvWork.wait( lock, [this]{ return !m_queue.empty() || m_exit.load( std::memory_order_acquire ); } );
        if( m_exit.load( std::memory_order_acquire ) ) return;
        auto f = m_queue.back();
        m_queue.pop_back();
        m_jobs++;
        lock.unlock();
        f();
        lock.lock();
        m_jobs--;
        if( m_jobs == 0 && m_queue.empty() ) m_cvJobs.notify_one();
        lock.unlock();
    }
}

}
