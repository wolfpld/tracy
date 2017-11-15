//---------------------------------------------------------
// For conditions of distribution and use, see
// https://github.com/preshing/cpp11-on-multicore/blob/master/LICENSE
//---------------------------------------------------------

#ifndef __CPP11OM_BENAPHORE_H__
#define __CPP11OM_BENAPHORE_H__

#include <cassert>
#include <thread>
#include <atomic>
#include "sema.h"


//---------------------------------------------------------
// NonRecursiveBenaphore
//---------------------------------------------------------
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


//---------------------------------------------------------
// RecursiveBenaphore
//---------------------------------------------------------
class RecursiveBenaphore
{
private:
    std::atomic<int> m_contentionCount;
    std::atomic<std::thread::id> m_owner;
    int m_recursion;
    DefaultSemaphoreType m_sema;

public:
    RecursiveBenaphore()
    : m_contentionCount(0)
// Apple LLVM 6.0 (in Xcode 6.1) refuses to initialize m_owner from a std::thread::id.
// "error: no viable conversion from 'std::__1::__thread_id' to '_Atomic(std::__1::__thread_id)'"
// (Note: On Linux, as of April 11, 2015, Clang 3.7 & libc++ don't have this problem.)
// Prefer atomic_init (below) when Apple LLVM is detected.
#if !(defined(__llvm__) && defined(__APPLE__))
    , m_owner(std::thread::id())
#endif
    , m_recursion(0)
    {
// GCC 4.7.2's libstdc++-v3 doesn't implement atomic_init.
// "warning: inline function 'void std::atomic_init(std::atomic<_ITp>*, _ITp) [with _ITp = std::thread::id]' used but never defined [enabled by default]"
// Using the constructor (above) in that case.
#if (defined(__llvm__) && defined(__APPLE__))
        std::atomic_init(&m_owner, std::thread::id());
#endif

        // If this assert fails on your system, you'll have to replace std::thread::id with a
        // more compact, platform-specific thread ID, or just comment the assert and live with
        // the extra overhead.
        assert(m_owner.is_lock_free());
    }

    void lock()
    {
        std::thread::id tid = std::this_thread::get_id();
        if (m_contentionCount.fetch_add(1, std::memory_order_acquire) > 0)
        {
            if (tid != m_owner.load(std::memory_order_relaxed))
                m_sema.wait();
        }
        //--- We are now inside the lock ---
        m_owner.store(tid, std::memory_order_relaxed);
        m_recursion++;
    }
 
    bool tryLock()
    {
        std::thread::id tid = std::this_thread::get_id();
        if (m_owner.load(std::memory_order_relaxed) == tid)
        {
            // Already inside the lock
            m_contentionCount.fetch_add(1, std::memory_order_relaxed);
        }
        else
        {
            if (m_contentionCount.load(std::memory_order_relaxed) != 0)
                return false;
            int expected = 0;
            if (!m_contentionCount.compare_exchange_strong(expected, 1, std::memory_order_acquire))
                return false;
            //--- We are now inside the lock ---
            m_owner.store(tid, std::memory_order_relaxed);
        }
        m_recursion++;
        return true;
    }

    void unlock()
    {
        assert(std::this_thread::get_id() == m_owner.load(std::memory_order_relaxed));
        int recur = --m_recursion;
        if (recur == 0)
            m_owner.store(std::thread::id(), std::memory_order_relaxed);
        if (m_contentionCount.fetch_sub(1, std::memory_order_release) > 1)
        {
            if (recur == 0)
                m_sema.signal();
        }
        //--- We are now outside the lock ---
    }
};


#endif // __CPP11OM_BENAPHORE_H__
