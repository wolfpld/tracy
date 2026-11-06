#ifdef TRACY_WEBSOCKET_SUPPORT

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "TracyAssert.hpp"
#include "TracySocket.hpp"
#include "TracySystem.hpp"

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  ifdef _MSC_VER
#    pragma warning(disable:4244)
#    pragma warning(disable:4267)
#  endif
#  define poll WSAPoll
#else
#  include <arpa/inet.h>
#  include <sys/socket.h>
#  include <poll.h>
#endif

namespace tracy
{

#ifdef _WIN32
typedef SOCKET socket_t;
#else
typedef int socket_t;
#endif

static inline char WsLower( char c )
{
    return c >= 'A' && c <= 'Z' ? c + ( 'a' - 'A' ) : c;
}

static inline bool WsIEq( const char* a, const char* b, size_t n )
{
    for( size_t i=0; i<n; i++ )
    {
        if( WsLower( a[i] ) != WsLower( b[i] ) ) return false;
    }
    return true;
}

static bool WsParseIPv4( const char* s, uint32_t& out )
{
    in_addr addr;
    if( inet_pton( AF_INET, s, &addr ) != 1 ) return false;
    out = ntohl( addr.s_addr );
    return true;
}

// A decimal number up to max, with nothing around it.
static bool WsParseUInt( const char* s, unsigned long max, int& out )
{
    // strtoul would skip spaces and accept a sign.
    if( *s < '0' || *s > '9' ) return false;
    char* end;
    const auto v = strtoul( s, &end, 10 );
    if( *end != '\0' || v > max ) return false;
    out = int( v );
    return true;
}

// Origins and allow-list entries are copied here, in lowercase. The scheme and the port are cut off with NULs.
struct WsAuthority
{
    char text[256];
    const char* scheme;     // nullptr when not specified
    const char* host;
    int port;               // -1 when not specified
};

// [scheme://]host[:port], host being a name, an IPv4 address, a [bracketed] IPv6 address, or a pattern.
static bool WsParseAuthority( const char* s, size_t n, WsAuthority& a )
{
    // The string functions below stop at a NUL, which would hide the rest of the origin.
    if( n == 0 || n >= sizeof( a.text ) || memchr( s, '\0', n ) ) return false;
    for( size_t i=0; i<n; i++ ) a.text[i] = WsLower( s[i] );
    a.text[n] = '\0';

    char* p = a.text;
    a.scheme = nullptr;
    if( char* sep = strstr( p, "://" ) )
    {
        *sep = '\0';
        a.scheme = p;
        p = sep + 3;
    }
    a.host = p;

    // The port follows the last ':', unless it is inside the brackets of an IPv6 address.
    char* colon;
    if( *p == '[' )
    {
        char* close = strchr( p, ']' );
        if( !close || ( close[1] != '\0' && close[1] != ':' ) ) return false;
        colon = close[1] == ':' ? close + 1 : nullptr;
    }
    else
    {
        colon = strrchr( p, ':' );
    }

    a.port = -1;
    if( colon )
    {
        *colon = '\0';
        if( strcmp( colon + 1, "*" ) != 0 && !WsParseUInt( colon + 1, 65535, a.port ) ) return false;
    }
    return *a.host != '\0';
}

static bool WsHostMatches( const WsAuthority& e, const WsAuthority& o )
{
    // CIDR range, matched against IPv4 literal origins only. Names are never resolved.
    if( const char* slash = strchr( e.host, '/' ) )
    {
        char netStr[16];
        const size_t netLen = slash - e.host;
        int bits;
        uint32_t net, ip;
        if( netLen >= sizeof( netStr ) || !WsParseUInt( slash + 1, 32, bits ) ) return false;
        memcpy( netStr, e.host, netLen );
        netStr[netLen] = '\0';
        if( !WsParseIPv4( netStr, net ) || !WsParseIPv4( o.host, ip ) ) return false;
        const uint32_t mask = bits == 0 ? 0 : ~uint32_t( 0 ) << ( 32 - bits );
        return ( ip & mask ) == ( net & mask );
    }
    if( strcmp( e.host, "*" ) == 0 ) return true;
    if( strncmp( e.host, "*.", 2 ) == 0 && e.host[2] != '\0' )
    {
        const auto suffix = e.host + 1;
        const auto suffixLen = strlen( suffix );
        const auto hostLen = strlen( o.host );
        return hostLen > suffixLen && strcmp( o.host + hostLen - suffixLen, suffix ) == 0;
    }
    return strcmp( e.host, o.host ) == 0;
}

// Whether origin matches an entry of allowList. See TRACY_WEBSOCKET_ORIGINS.
static bool WebSocketOriginAllowed( const char* origin, size_t len, const char* allowList )
{
    WsAuthority o;
    const bool valid = WsParseAuthority( origin, len, o ) && o.scheme && ( strcmp( o.scheme, "https" ) == 0 || strcmp( o.scheme, "http" ) == 0 );
    // An origin that is not http or https, such as "null", is only matched by "*".
    if( !valid )
    {
        o.scheme = "";
        o.host = "";
        o.port = -1;
    }
    const bool https = strcmp( o.scheme, "https" ) == 0;
    const int port = o.port != -1 ? o.port : ( https ? 443 : 80 );

    // Loopback origins are always allowed.
    uint32_t ip;
    if( valid && ( strcmp( o.host, "localhost" ) == 0 || strcmp( o.host, "[::1]" ) == 0 || ( WsParseIPv4( o.host, ip ) && ( ip >> 24 ) == 127 ) ) )
    {
        return true;
    }

    if( !allowList ) return false;
    constexpr char Separators[] = ",; \t\r\n";
    for( auto p = allowList; *( p += strspn( p, Separators ) ) != '\0'; )
    {
        const auto entry = p;
        auto entryLen = strcspn( p, Separators );
        p += entryLen;
        // A trailing slash is allowed, as in a URL.
        while( entryLen > 1 && entry[entryLen-1] == '/' ) entryLen--;

        WsAuthority e;
        if( !WsParseAuthority( entry, entryLen, e ) ) continue;
        if( e.scheme && strcmp( e.scheme, o.scheme ) != 0 ) continue;
        if( e.port != -1 && e.port != port ) continue;
        if( WsHostMatches( e, o ) ) return true;
    }
    return false;
}

}

#endif
