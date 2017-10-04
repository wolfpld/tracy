#ifndef __TRACYLOCK_HPP__
#define __TRACYLOCK_HPP__

#include "TracyProfiler.hpp"

namespace tracy
{

template<class T>
class Lockable
{
public:
    Lockable( const SourceLocation* srcloc )
    {
        Magic magic;
        auto& token = s_token;
        auto item = s_queue.enqueue_begin( token, magic );
        item->hdr.type = QueueType::LockAnnounce;
        item->lockAnnounce.id = (uint64_t)&m_lockable;
        item->lockAnnounce.srcloc = (uint64_t)srcloc;
        s_queue.enqueue_finish( token, magic );
    }

    Lockable( const Lockable& ) = delete;
    Lockable& operator=( const Lockable& ) = delete;

    void lock()
    {
        m_lockable.lock();
    }

    void unlock()
    {
        m_lockable.unlock();
    }

    bool try_lock()
    {
        return m_lockable.try_lock();
    }

private:
    T m_lockable;
};

};

#endif
