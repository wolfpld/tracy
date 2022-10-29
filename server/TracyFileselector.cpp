#include "TracyFileselector.hpp"

#ifndef TRACY_NO_FILESELECTOR
#  ifdef __EMSCRIPTEN__
#    include <emscripten.h>
#  else
#    include "../nfd/nfd.h"
#  endif
#endif

namespace tracy::Fileselector
{

static bool s_hasFailed = false;

void Init()
{
#if !defined TRACY_NO_FILESELECTOR && !defined __EMSCRIPTEN__
    NFD_Init();
#endif
}

void Shutdown()
{
#if !defined TRACY_NO_FILESELECTOR && !defined __EMSCRIPTEN__
    NFD_Quit();
#endif
}

bool HasFailed()
{
    if( s_hasFailed )
    {
        s_hasFailed = false;
        return true;
    }
    else
    {
        return false;
    }
}

#ifdef __EMSCRIPTEN__
static std::function<void(const char*)> s_openFileCallback;

extern "C" int nativeOpenFile()
{
    s_openFileCallback( "upload.tracy" );
    return 0;
}
#endif

static bool OpenFileImpl( const char* ext, const char* desc, std::function<void(const char*)> callback )
{
#ifndef TRACY_NO_FILESELECTOR
#  ifdef __EMSCRIPTEN__
    s_openFileCallback = callback;
    EM_ASM( {
        var input = document.createElement( 'input' );
        input.type = 'file';
        input.accept = UTF8ToString( $0 );
        input.onchange = (e) => {
            var file = e.target.files[0];
            var reader = new FileReader();
            reader.readAsArrayBuffer( file );
            reader.onload = () => {
                var buf = reader.result;
                var view = new Uint8Array( buf );
                FS.createDataFile( '/', 'upload.tracy', view, true, true );
                Module.ccall( 'nativeOpenFile', 'number', [], [] );
                FS.unlink( '/upload.tracy' );
            };
        };
        input.click();
    }, ext );
    return true;
#  else
    nfdu8filteritem_t filter = { desc, ext };
    nfdu8char_t* fn;
    const auto res = NFD_OpenDialogU8( &fn, &filter, 1, nullptr );
    if( res == NFD_OKAY )
    {
        callback( (const char*)fn );
        NFD_FreePathU8( fn );
        return true;
    }
    else
    {
        return res != NFD_ERROR;
    }
#  endif
#endif
    return false;
}

static bool SaveFileImpl( const char* ext, const char* desc, std::function<void(const char*)> callback )
{
#if !defined TRACY_NO_FILESELECTOR && !defined __EMSCRIPTEN__
    nfdu8filteritem_t filter = { desc, ext };
    nfdu8char_t* fn;
    const auto res = NFD_SaveDialogU8( &fn, &filter, 1, nullptr, nullptr );
    if( res == NFD_OKAY )
    {
        callback( (const char*)fn );
        NFD_FreePathU8( fn );
        return true;
    }
    else
    {
        return res != NFD_ERROR;
    }
#endif
    return false;
}

void OpenFile( const char* ext, const char* desc, std::function<void(const char*)> callback )
{
    if( !OpenFileImpl( ext, desc, callback ) ) s_hasFailed = true;
}

void SaveFile( const char* ext, const char* desc, std::function<void(const char*)> callback )
{
    if( !SaveFileImpl( ext, desc, callback ) ) s_hasFailed = true;
}

}
