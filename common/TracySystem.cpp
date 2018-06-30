#ifdef _WIN32
#  include <windows.h>
#else
#  include <pthread.h>
#  include <string.h>
#  include <unistd.h>
#endif

#include <inttypes.h>
#include <stdio.h>

#include "TracySystem.hpp"

#ifdef TRACY_COLLECT_THREAD_NAMES
#  include <atomic>
#  include "TracyAlloc.hpp"
#endif

namespace tracy
{

#ifdef TRACY_COLLECT_THREAD_NAMES
struct ThreadNameData
{
    uint64_t id;
    const char* name;
    ThreadNameData* next;
};
extern std::atomic<ThreadNameData*> s_threadNameData;
#endif

void SetThreadName( std::thread& thread, const char* name )
{
    SetThreadName( thread.native_handle(), name );
}

void SetThreadName( std::thread::native_handle_type handle, const char* name )
{
#ifdef _WIN32
#  ifdef NTDDI_WIN10_RS2
    wchar_t buf[256];
    mbstowcs( buf, name, 256 );
    SetThreadDescription( static_cast<HANDLE>( handle ), buf );
#  else
    const DWORD MS_VC_EXCEPTION=0x406D1388;
#    pragma pack( push, 8 )
    struct THREADNAME_INFO
    {
        DWORD dwType;
        LPCSTR szName;
        DWORD dwThreadID;
        DWORD dwFlags;
    };
#    pragma pack(pop)

    DWORD ThreadId = GetThreadId( static_cast<HANDLE>( handle ) );
    THREADNAME_INFO info;
    info.dwType = 0x1000;
    info.szName = name;
    info.dwThreadID = ThreadId;
    info.dwFlags = 0;

    __try
    {
        RaiseException( MS_VC_EXCEPTION, 0, sizeof(info)/sizeof(ULONG_PTR), (ULONG_PTR*)&info );
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }
#  endif
#elif defined _GNU_SOURCE && !defined __EMSCRIPTEN__
    {
        const auto sz = strlen( name );
        if( sz <= 15 )
        {
            pthread_setname_np( handle, name );
        }
        else
        {
            char buf[16];
            memcpy( buf, name, 15 );
            buf[15] = '\0';
            pthread_setname_np( handle, buf );
        }
    }
#endif
#ifdef TRACY_COLLECT_THREAD_NAMES
    {
        rpmalloc_thread_initialize();
        const auto sz = strlen( name );
        char* buf = (char*)tracy_malloc( sz+1 );
        memcpy( buf, name, sz );
        buf[sz+1] = '\0';
        auto data = (ThreadNameData*)tracy_malloc( sizeof( ThreadNameData ) );
#  ifdef _WIN32
        data->id = GetThreadId( static_cast<HANDLE>( handle ) );
#  elif defined __APPLE__
        pthread_threadid_np( handle, &data->id );
#  else
        data->id = (uint64_t)handle;
#  endif
        data->name = buf;
        data->next = s_threadNameData.load( std::memory_order_relaxed );
        while( !s_threadNameData.compare_exchange_weak( data->next, data, std::memory_order_release, std::memory_order_relaxed ) ) {}
    }
#endif
}

const char* GetThreadName( uint64_t id )
{
    static char buf[256];
#ifdef TRACY_COLLECT_THREAD_NAMES
    auto ptr = s_threadNameData.load( std::memory_order_relaxed );
    while( ptr )
    {
        if( ptr->id == id )
        {
            return ptr->name;
        }
        ptr = ptr->next;
    }
#else
#  ifdef _WIN32
#    ifdef NTDDI_WIN10_RS2
    auto hnd = OpenThread( THREAD_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)id );
    if( hnd != 0 )
    {
        PWSTR tmp;
        GetThreadDescription( hnd, &tmp );
        auto ret = wcstombs( buf, tmp, 256 );
        CloseHandle( hnd );
        if( ret != 0 )
        {
            return buf;
        }
    }
#    endif
#  elif defined _GNU_SOURCE && !defined __ANDROID__ && !defined __EMSCRIPTEN__
    if( pthread_getname_np( (pthread_t)id, buf, 256 ) == 0 )
    {
        return buf;
    }
#  endif
#endif
    sprintf( buf, "%" PRIu64, id );
    return buf;
}

}
