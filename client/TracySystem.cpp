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
    const DWORD MS_VC_EXCEPTION=0x406D1388;

#  pragma pack( push, 8 )
    struct THREADNAME_INFO
    {
        DWORD dwType;
        LPCSTR szName;
        DWORD dwThreadID;
        DWORD dwFlags;
    };
#  pragma pack(pop)

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
#else
    pthread_setname_np( thread.native_handle(), name );
#endif

}

}