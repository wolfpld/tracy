#ifdef __MINGW32__
#  define __STDC_FORMAT_MACROS
#endif
#include <assert.h>
#include <inttypes.h>
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
        if( pos == 2 && path[1] == ':' ) continue;    // Don't create drive name.
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

static void GetConfigDirectory( char* buf, size_t& sz )
{
#ifdef _WIN32
    auto path = getenv( "APPDATA" );
    sz = strlen( path );
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
}

const char* GetSavePath( const char* file )
{
    assert( file && *file );

    enum { Pool = 8 };
    enum { MaxPath = 512 };
    static char bufpool[Pool][MaxPath];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    size_t sz;
    GetConfigDirectory( buf, sz );

    memcpy( buf+sz, "/tracy/", 8 );
    sz += 7;

    auto status = CreateDirStruct( buf );
    assert( status );

    const auto fsz = strlen( file );
    assert( sz + fsz < MaxPath );
    memcpy( buf+sz, file, fsz+1 );

    return buf;
}

const char* GetSavePath( const char* program, uint64_t time, const char* file, bool create )
{
    assert( program && *program );

    enum { Pool = 8 };
    enum { MaxPath = 512 };
    static char bufpool[Pool][MaxPath];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    size_t sz;
    GetConfigDirectory( buf, sz );

    const auto psz = strlen( program );
    assert( psz < 512 );
    char tmp[512];
    strcpy( tmp, program );
    for( size_t i=0; i<psz; i++ )
    {
        switch( tmp[i] )
        {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
        case 16:
        case 17:
        case 18:
        case 19:
        case 20:
        case 21:
        case 22:
        case 23:
        case 24:
        case 25:
        case 26:
        case 27:
        case 28:
        case 29:
        case 30:
        case 31:
        case 0x7F:
        case '<':
        case '>':
        case ':':
        case '"':
        case '/':
        case '\\':
        case '|':
        case '?':
        case '*':
            tmp[i] = '_';
            break;
        default:
            break;
        }
    }

    // 604800 = 7 days
    sz += sprintf( buf+sz, "/tracy/user/%c/%s/%" PRIu64 "/%" PRIu64 "/", tmp[0], tmp, uint64_t( time / 604800 ), time );

    if( create )
    {
        auto status = CreateDirStruct( buf );
        assert( status );
    }

    if( file )
    {
        const auto fsz = strlen( file );
        assert( sz + fsz < MaxPath );
        memcpy( buf+sz, file, fsz+1 );
    }
    else
    {
        buf[sz] = '\0';
    }

    return buf;
}

}
