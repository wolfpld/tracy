#ifdef _WIN32
#  include <windows.h>
#  include <shellapi.h>
#else
#  include <stdio.h>
#  include <stdlib.h>
#endif

#include "TracyWeb.hpp"

namespace tracy
{

void OpenWebpage( const char* url )
{
#ifdef _WIN32
    ShellExecuteA( nullptr, nullptr, url, nullptr, nullptr, 0 );
#elif defined __APPLE__
    char buf[1024];
    sprintf( buf, "open %s", url );
    system( buf );
#else
    char buf[1024];
    sprintf( buf, "xdg-open %s", url );
    system( buf );
#endif
}

}
