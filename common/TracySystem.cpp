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
    wchar_t buf[256];
    mbstowcs( buf, name, 256 );
    SetThreadDescription( static_cast<HANDLE>( thread.native_handle() ), buf );
#else
    pthread_setname_np( thread.native_handle(), name );
#endif

}

}