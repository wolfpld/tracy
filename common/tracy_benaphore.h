// Copyright (c) 2015 Jeff Preshing
//
// This software is provided 'as-is', without any express or implied
// warranty. In no event will the authors be held liable for any damages
// arising from the use of this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
// 1. The origin of this software must not be misrepresented; you must not
// claim that you wrote the original software. If you use this software
// in a product, an acknowledgement in the product documentation would be
// appreciated but is not required.
// 2. Altered source versions must be plainly marked as such, and must not be
// misrepresented as being the original software.
// 3. This notice may not be removed or altered from any source distribution.

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

    bool try_lock()
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
