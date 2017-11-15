//---------------------------------------------------------
// For conditions of distribution and use, see
// https://github.com/preshing/cpp11-on-multicore/blob/master/LICENSE
//---------------------------------------------------------

#ifndef __TRACY_CPP11OM_BENAPHORE_H__
#define __TRACY_CPP11OM_BENAPHORE_H__

#include <cassert>
#include <thread>
#include <atomic>
#include "tracy_sema.h"

namespace tracy
{

class NonRecursiveBenaphore
{
private:
    std::atomic<int> m_contentionCount;
    DefaultSemaphoreType m_sema;

public:
    NonRecursiveBenaphore() : m_contentionCount(0) {}

    void lock()
    {
        if (m_contentionCount.fetch_add(1, std::memory_order_acquire) > 0)
        {
            m_sema.wait();
        }
    }

    bool tryLock()
    {
        if (m_contentionCount.load(std::memory_order_relaxed) != 0)
            return false;
        int expected = 0;
        return m_contentionCount.compare_exchange_strong(expected, 1, std::memory_order_acquire);
    }

    void unlock()
    {
        int oldCount = m_contentionCount.fetch_sub(1, std::memory_order_release);
        assert(oldCount > 0);
        if (oldCount > 1)
        {
            m_sema.signal();
        }
    }
};

}

#endif // __CPP11OM_BENAPHORE_H__
