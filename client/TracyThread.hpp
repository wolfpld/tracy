#ifndef __TRACYTHREAD_HPP__
#define __TRACYTHREAD_HPP__

#include <stdint.h>
#include <thread>

#ifdef _MSC_VER
#include <windows.h>
#else
#include <pthread.h>
#endif

namespace tracy
{

    static inline uint64_t GetThreadHandle()
    {
#ifdef _MSC_VER
        static_assert( sizeof( decltype( GetCurrentThreadId() ) ) <= sizeof( uint64_t ), "Thread handle too big to fit in protocol" );
        return uint64_t( GetCurrentThreadId() );
#else
        static_assert( sizeof( decltype( pthread_self() ) ) <= sizeof( uint64_t ), "Thread handle too big to fit in protocol" );
        return uint64_t( pthread_self() );
#endif
    }

}

#endif
