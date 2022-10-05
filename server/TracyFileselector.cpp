#include "TracyFileselector.hpp"

#ifndef TRACY_NO_FILESELECTOR
#  include "../nfd/nfd.h"
#endif

namespace tracy::Fileselector
{

void Init()
{
#ifndef TRACY_NO_FILESELECTOR
    NFD_Init();
#endif
}

void Shutdown()
{
#ifndef TRACY_NO_FILESELECTOR
    NFD_Quit();
#endif
}

std::string OpenFile( const char* ext, const char* desc )
{
    std::string ret;
#ifndef TRACY_NO_FILESELECTOR
    nfdu8filteritem_t filter = { desc, ext };
    nfdu8char_t* fn;
    if( NFD_OpenDialogU8( &fn, &filter, 1, nullptr ) == NFD_OKAY )
    {
        ret.assign( fn );
        NFD_FreePathU8( fn );
    }
#endif
    return ret;
}

std::string SaveFile( const char* ext, const char* desc )
{
    std::string ret;
#ifndef TRACY_NO_FILESELECTOR
    nfdu8filteritem_t filter = { desc, ext };
    nfdu8char_t* fn;
    if( NFD_SaveDialogU8( &fn, &filter, 1, nullptr, nullptr ) == NFD_OKAY )
    {
        ret.assign( fn );
        NFD_FreePathU8( fn );
    }
#endif
    return ret;
}

}
