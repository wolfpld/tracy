#ifndef __TRACYTHREAD_HPP__
#define __TRACYTHREAD_HPP__

#include <inttypes.h>
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

    static inline const char* GetThreadName( uint64_t id )
    {
        static char buf[256];
#ifdef _MSC_VER
#  ifdef NTDDI_WIN10_RS2
        auto hnd = OpenThread( THREAD_QUERY_LIMITED_INFORMATION, FALSE, id );
        PWSTR tmp;
        GetThreadDescription( hnd, &tmp );
        auto ret = wcstombs( buf, tmp, 256 );
        CloseHandle( hnd );
        if( ret != 0 )
        {
            return buf;
        }
#  endif
#else
        if( pthread_getname_np( (pthread_t)id, buf, 256 ) == 0 )
        {
            return buf;
        }
#endif
        sprintf( buf, "%" PRIu64, id );
        return buf;
    }

}

#endif
