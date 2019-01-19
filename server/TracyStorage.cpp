#include <assert.h>
#include <string>
#include <string.h>

#ifdef _WIN32
#  include <direct.h>
#  include <windows.h>
#else
#  include <dirent.h>
#  include <sys/types.h>
#  include <unistd.h>
#  include <errno.h>
#endif
#include <sys/stat.h>

#include "TracyStorage.hpp"

namespace tracy
{

static bool CreateDirStruct( const std::string& path )
{
    struct stat buf;
    if( stat( path.c_str(), &buf ) == 0 ) return true;

    if( errno != ENOENT )
    {
        return false;
    }

    size_t pos = 0;
    do
    {
        pos = path.find( '/', pos+1 );
#ifdef _WIN32
        if( pos == 2 ) continue;    // Don't create drive name.
        if( _mkdir( path.substr( 0, pos ).c_str() ) != 0 )
#else
        if( mkdir( path.substr( 0, pos ).c_str(), S_IRWXU ) != 0 )
#endif
        {
            if( errno != EEXIST )
            {
                return false;
            }
        }
    }
    while( pos != std::string::npos );

    return true;
}

const char* GetSavePath( const char* file )
{
    enum { Pool = 8 };
    enum { MaxPath = 512 };
    static char bufpool[Pool][MaxPath];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

#ifdef _WIN32
    auto path = getenv( "APPDATA" );
    auto sz = strlen( path );
    memcpy( buf, path, sz );

    for( size_t i=0; i<sz; i++ )
    {
        if( buf[i] == '\\' )
        {
            buf[i] = '/';
        }
    }
#else
    auto path = getenv( "XDG_CONFIG_HOME" );
    size_t sz;
    if( path && *path )
    {
        sz = strlen( path );
        memcpy( buf, path, sz );
    }
    else
    {
        path = getenv( "HOME" );
        assert( path && *path );

        sz = strlen( path );
        memcpy( buf, path, sz );
        memcpy( buf+sz, "/.config", 8 );
        sz += 8;
    }
#endif

    memcpy( buf+sz, "/tracy/", 8 );
    sz += 7;

    auto status = CreateDirStruct( buf );
    assert( status );

    const auto fsz = strlen( file );
    assert( sz + fsz < MaxPath );
    memcpy( buf+sz, file, fsz+1 );

    return buf;
}

}
