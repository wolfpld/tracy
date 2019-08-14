#ifndef __TRACYSYSTEM_HPP__
#define __TRACYSYSTEM_HPP__

#ifdef TRACY_ENABLE
#  if defined __ANDROID__ || defined __CYGWIN__ || defined __APPLE__ || defined _GNU_SOURCE || ( defined _WIN32 && ( !defined NTDDI_WIN10_RS2 || NTDDI_VERSION < NTDDI_WIN10_RS2 ) )
#    define TRACY_COLLECT_THREAD_NAMES
#  endif
#endif

#if defined _WIN32 || defined __CYGWIN__
#  ifndef _WINDOWS_
extern "C" __declspec(dllimport) unsigned long __stdcall GetCurrentThreadId(void);
#  endif
#else
#  include <pthread.h>
#endif

#ifdef __ANDROID__
#  include <sys/types.h>
#elif defined __linux__
#  include <unistd.h>
#  include <sys/syscall.h>
#endif

#include <stdint.h>

#include "TracyApi.h"

namespace tracy
{

namespace detail
{
static inline uint64_t GetThreadHandleImpl()
{
#if defined _WIN32 || defined __CYGWIN__
    static_assert( sizeof( decltype( GetCurrentThreadId() ) ) <= sizeof( uint64_t ), "Thread handle too big to fit in protocol" );
    return uint64_t( GetCurrentThreadId() );
#elif defined __APPLE__
    uint64_t id;
    pthread_threadid_np( pthread_self(), &id );
    return id;
#elif defined __ANDROID__
    return (uint64_t)gettid();
#elif defined __linux__
    return (uint64_t)syscall( SYS_gettid );
#else
    static_assert( sizeof( decltype( pthread_self() ) ) <= sizeof( uint64_t ), "Thread handle too big to fit in protocol" );
    return uint64_t( pthread_self() );
#endif
}
}

#ifdef TRACY_ENABLE
TRACY_API uint64_t GetThreadHandle();
#else
static inline uint64_t GetThreadHandle()
{
    return detail::GetThreadHandleImpl();
}
#endif

void SetThreadName( const char* name );
const char* GetThreadName( uint64_t id );

}

#endif
