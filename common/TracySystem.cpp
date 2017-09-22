#ifdef _WIN32
#  include <windows.h>
#else
#  include <pthread.h>
#  include <unistd.h>
#endif


#include "TracySystem.hpp"

namespace tracy
{

const char* PointerCheckA = "tracy";

void SetThreadName( std::thread& thread, const char* name )
{
#ifdef _WIN32
#  ifdef NTDDI_WIN10_RS2
    wchar_t buf[256];
    mbstowcs( buf, name, 256 );
    SetThreadDescription( static_cast<HANDLE>( thread.native_handle() ), buf );
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

    DWORD ThreadId = GetThreadId( static_cast<HANDLE>( thread.native_handle() ) );
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
#else
    const auto sz = strlen( name );
    if( sz <= 15 )
    {
        pthread_setname_np( thread.native_handle(), name );
    }
    else
    {
        char buf[16];
        memcpy( buf, name, 15 );
        buf[15] = '\0';
        pthread_setname_np( thread.native_handle(), sz );
    }
#endif
}

}