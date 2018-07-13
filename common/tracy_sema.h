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

#ifndef __TRACY_CPP11OM_SEMAPHORE_H__
#define __TRACY_CPP11OM_SEMAPHORE_H__

#include <atomic>
#include <cassert>

#if defined(__MACH__)
    #include <mach/mach.h>
#elif defined(__unix__)
    #include <semaphore.h>
#endif

namespace tracy
{

#if defined(_WIN32)
//---------------------------------------------------------
// Semaphore (Windows)
//---------------------------------------------------------
#ifndef MAXLONG
enum { MAXLONG = 0x7fffffff };
#endif

#ifndef INFINITE
enum { INFINITE = 0xFFFFFFFF };
#endif

#ifndef _WINDOWS_
typedef void* HANDLE;

extern "C" __declspec(dllimport) HANDLE __stdcall CreateSemaphoreA( void*, long, long, const char* );
extern "C" __declspec(dllimport) int __stdcall CloseHandle( HANDLE );
extern "C" __declspec(dllimport) unsigned long __stdcall WaitForSingleObject( HANDLE, unsigned long );
extern "C" __declspec(dllimport) int __stdcall ReleaseSemaphore( HANDLE, long, long* );
#endif

class Semaphore
{
private:
    HANDLE m_hSema;

    Semaphore(const Semaphore& other) = delete;
    Semaphore& operator=(const Semaphore& other) = delete;

public:
    Semaphore(int initialCount = 0)
    {
        assert(initialCount >= 0);
        m_hSema = CreateSemaphoreA(NULL, initialCount, MAXLONG, NULL);
    }

    ~Semaphore()
    {
        CloseHandle(m_hSema);
    }

    void wait()
    {
        WaitForSingleObject(m_hSema, INFINITE);
    }

    void signal(int count = 1)
    {
        ReleaseSemaphore(m_hSema, count, NULL);
    }
};


#elif defined(__MACH__)
//---------------------------------------------------------
// Semaphore (Apple iOS and OSX)
// Can't use POSIX semaphores due to http://lists.apple.com/archives/darwin-kernel/2009/Apr/msg00010.html
//---------------------------------------------------------

class Semaphore
{
private:
    semaphore_t m_sema;

    Semaphore(const Semaphore& other) = delete;
    Semaphore& operator=(const Semaphore& other) = delete;

public:
    Semaphore(int initialCount = 0)
    {
        assert(initialCount >= 0);
        semaphore_create(mach_task_self(), &m_sema, SYNC_POLICY_FIFO, initialCount);
    }

    ~Semaphore()
    {
        semaphore_destroy(mach_task_self(), m_sema);
    }

    void wait()
    {
        semaphore_wait(m_sema);
    }

    void signal()
    {
        semaphore_signal(m_sema);
    }

    void signal(int count)
    {
        while (count-- > 0)
        {
            semaphore_signal(m_sema);
        }
    }
};


#elif defined(__unix__)
//---------------------------------------------------------
// Semaphore (POSIX, Linux)
//---------------------------------------------------------

class Semaphore
{
private:
    sem_t m_sema;

    Semaphore(const Semaphore& other) = delete;
    Semaphore& operator=(const Semaphore& other) = delete;

public:
    Semaphore(int initialCount = 0)
    {
        assert(initialCount >= 0);
        sem_init(&m_sema, 0, initialCount);
    }

    ~Semaphore()
    {
        sem_destroy(&m_sema);
    }

    void wait()
    {
        // http://stackoverflow.com/questions/2013181/gdb-causes-sem-wait-to-fail-with-eintr-error
        int rc;
        do
        {
            rc = sem_wait(&m_sema);
        }
        while (rc == -1 && errno == EINTR);
    }

    void signal()
    {
        sem_post(&m_sema);
    }

    void signal(int count)
    {
        while (count-- > 0)
        {
            sem_post(&m_sema);
        }
    }
};


#else

#error Unsupported platform!

#endif


//---------------------------------------------------------
// LightweightSemaphore
//---------------------------------------------------------
class LightweightSemaphore
{
private:
    std::atomic<int> m_count;
    Semaphore m_sema;

    void waitWithPartialSpinning()
    {
        int oldCount;
        // Is there a better way to set the initial spin count?
        // If we lower it to 1000, testBenaphore becomes 15x slower on my Core i7-5930K Windows PC,
        // as threads start hitting the kernel semaphore.
        int spin = 10000;
        while (spin--)
        {
            oldCount = m_count.load(std::memory_order_relaxed);
            if ((oldCount > 0) && m_count.compare_exchange_strong(oldCount, oldCount - 1, std::memory_order_acquire))
                return;
            std::atomic_signal_fence(std::memory_order_acquire);     // Prevent the compiler from collapsing the loop.
        }
        oldCount = m_count.fetch_sub(1, std::memory_order_acquire);
        if (oldCount <= 0)
        {
            m_sema.wait();
        }
    }

public:
    LightweightSemaphore(int initialCount = 0) : m_count(initialCount)
    {
        assert(initialCount >= 0);
    }

    bool tryWait()
    {
        int oldCount = m_count.load(std::memory_order_relaxed);
        return (oldCount > 0 && m_count.compare_exchange_strong(oldCount, oldCount - 1, std::memory_order_acquire));
    }

    void wait()
    {
        if (!tryWait())
            waitWithPartialSpinning();
    }

    void signal(int count = 1)
    {
        int oldCount = m_count.fetch_add(count, std::memory_order_release);
        int toRelease = -oldCount < count ? -oldCount : count;
        if (toRelease > 0)
        {
            m_sema.signal(toRelease);
        }
    }
};


typedef LightweightSemaphore DefaultSemaphoreType;

}

#endif // __CPP11OM_SEMAPHORE_H__
