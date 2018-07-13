#ifndef __TRACYSYSTEM_HPP__
#define __TRACYSYSTEM_HPP__

#ifdef TRACY_ENABLE
#  if defined __ANDROID__ || defined __CYGWIN__ || defined __APPLE__ || defined _GNU_SOURCE || ( defined _WIN32 && !defined NTDDI_WIN10_RS2 )
#    define TRACY_COLLECT_THREAD_NAMES
#  endif
#endif

#ifdef _WIN32
#ifndef _WINDOWS_
extern "C" __declspec(dllimport) unsigned long __stdcall GetCurrentThreadId(void);
#endif
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
#elif defined __APPLE__
    uint64_t id;
    pthread_threadid_np( pthread_self(), &id );
    return id;
#else
    static_assert( sizeof( decltype( pthread_self() ) ) <= sizeof( uint64_t ), "Thread handle too big to fit in protocol" );
    return uint64_t( pthread_self() );
#endif
}

void SetThreadName( std::thread& thread, const char* name );
void SetThreadName( std::thread::native_handle_type handle, const char* name );
const char* GetThreadName( uint64_t id );

}

#endif
