#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../public/common/TracySocket.hpp"
#include "../public/common/TracyVersion.hpp"
#include "HttpRequest.hpp"

#if defined _WIN32
#  include <windows.h>
extern "C" typedef LONG (WINAPI *t_RtlGetVersion)( PRTL_OSVERSIONINFOW );
#elif defined __linux__
#  include <sys/utsname.h>
#elif defined __APPLE__
#  include "TargetConditionals.h"
#endif

static constexpr char CRLF[2] = { '\r', '\n' };

static const char* GetOsInfo()
{
    static char buf[1024];
#if defined _WIN32
    t_RtlGetVersion RtlGetVersion = (t_RtlGetVersion)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "RtlGetVersion" );
    if( !RtlGetVersion )
    {
#  ifdef __MINGW32__
        sprintf( buf, "Windows (MingW)" );
#  else
        sprintf( buf, "Windows" );
#  endif
    }
    else
    {
        RTL_OSVERSIONINFOW ver = { sizeof( RTL_OSVERSIONINFOW ) };
        RtlGetVersion( &ver );

#  ifdef __MINGW32__
        sprintf( buf, "Windows %i.%i.%i (MingW)", (int)ver.dwMajorVersion, (int)ver.dwMinorVersion, (int)ver.dwBuildNumber );
#  else
        sprintf( buf, "Windows %i.%i.%i", ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber );
#  endif
    }
#elif defined __linux__
    struct utsname utsName;
    uname( &utsName );
#  if defined __ANDROID__
    sprintf( buf, "Linux %s (Android)", utsName.release );
#  else
    sprintf( buf, "Linux %s", utsName.release );
#  endif
#elif defined __APPLE__
#  if TARGET_OS_IPHONE == 1
    sprintf( buf, "Darwin (iOS)" );
#  elif TARGET_OS_MAC == 1
    sprintf( buf, "Darwin (OSX)" );
#  else
    sprintf( buf, "Darwin (unknown)" );
#  endif
#elif defined __DragonFly__
    sprintf( buf, "BSD (DragonFly)" );
#elif defined __FreeBSD__
    sprintf( buf, "BSD (FreeBSD)" );
#elif defined __NetBSD__
    sprintf( buf, "BSD (NetBSD)" );
#elif defined __OpenBSD__
    sprintf( buf, "BSD (OpenBSD)" );
#else
    sprintf( buf, "unknown" );
#endif
    return buf;
}

void HttpRequest( const char* server, const char* resource, int port, const std::function<void(int, char*)>& cb )
{
    tracy::Socket sock;
    if( !sock.ConnectBlocking( server, port ) ) return;
    char request[4096];
    const auto len = sprintf( request, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Tracy Profiler %i.%i.%i (%s)\r\nConnection: close\r\nCache-Control: no-cache, no-store, must-revalidate\r\n\r\n", resource, server, tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, GetOsInfo() );
    sock.Send( request, len );
    char response[4096];
    const auto sz = sock.ReadUpTo( response, 4096 );
    if( sz < 13 ) return;
    if( memcmp( response, "HTTP/1.1 200", 12 ) != 0 ) return;
    auto hdr = response + 13;
    int contentLength = 0;
    for(;;)
    {
        while( memcmp( hdr, CRLF, 2 ) != 0 ) hdr++;
        hdr += 2;
        if( memcmp( hdr, "Content-Length: ", 16 ) == 0 )
        {
            hdr += 16;
            contentLength = atoi( hdr );
            break;
        }
    }
    assert( contentLength != 0 );
    for(;;)
    {
        while( memcmp( hdr, CRLF, 2 ) != 0 ) hdr++;
        hdr += 2;
        if( memcmp( hdr, CRLF, 2 ) == 0 )
        {
            hdr += 2;
            break;
        }
        hdr += 2;
    }

    const auto hdrSize = hdr - response;
    const auto partSize = sz - hdrSize;
    char* data = new char[contentLength];
    memcpy( data, hdr, partSize );
    auto remaining = contentLength - partSize;
    if( remaining > 0 ) sock.Read( data + partSize, remaining, 15 );

    cb( contentLength, data );
}
