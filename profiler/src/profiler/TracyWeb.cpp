#ifdef _WIN32
#  include <windows.h>
#  include <shellapi.h>
#elif defined __EMSCRIPTEN__
#  include <emscripten.h>
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
    snprintf( buf, sizeof(buf), "open %s", url );
    system( buf );
#elif defined __EMSCRIPTEN__
    EM_ASM( { window.open( UTF8ToString( $0 ), '_blank' ) }, url );
#else
    char buf[1024];
    snprintf( buf, sizeof(buf), "xdg-open %s", url );
    system( buf );
#endif
}

}
