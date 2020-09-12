#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/TracySocket.hpp"
#include "../server/TracyVersion.hpp"
#include "HttpRequest.hpp"

static constexpr char CRLF[2] = { '\r', '\n' };

void HttpRequest( const char* server, const char* resource, int port, std::function<void(int, char*)> cb )
{
    tracy::Socket sock;
    if( !sock.ConnectBlocking( server, port ) ) return;
    char request[4096];
    const auto len = sprintf( request, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Tracy Profiler %i.%i.%i\r\nConnection: close\r\nCache-Control: no-cache, no-store, must-revalidate\r\n\r\n", resource, server, tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch );
    sock.Send( request, len );
    char response[4096];
    const auto sz = sock.ReadUpTo( response, 4096, 15 );
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
