#ifndef __TRACYSYSTEM_HPP__
#define __TRACYSYSTEM_HPP__

#ifdef _WIN32
extern "C" __declspec(dllimport) unsigned long __stdcall GetCurrentThreadId(void);
#else
#  include <pthread.h>
#endif

#include <stdint.h>
#include <thread>

namespace tracy
{

static inline uint64_t GetThreadHandle()
{
#ifdef _WIN32
    static_assert( sizeof( decltype( GetCurrentThreadId() ) ) <= sizeof( uint64_t ), "Thread handle too big to fit in protocol" );
    return uint64_t( GetCurrentThreadId() );
#else
    static_assert( sizeof( decltype( pthread_self() ) ) <= sizeof( uint64_t ), "Thread handle too big to fit in protocol" );
    return uint64_t( pthread_self() );
#endif
}

void SetThreadName( std::thread& thread, const char* name );
const char* GetThreadName( uint64_t id );

}

#endif
