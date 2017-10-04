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
