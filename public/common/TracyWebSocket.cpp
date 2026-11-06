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

// The value of TRACY_WEBSOCKET_ORIGINS, or nullptr. GetEnvVar can't be used on Windows, it cuts long values and shares one buffer.
static const char* WsEnvOrigins( char* buf, size_t size )
{
#ifdef _WIN32
    const auto n = GetEnvironmentVariableA( "TRACY_WEBSOCKET_ORIGINS", buf, DWORD( size ) );
    return n > 0 && n < size ? buf : nullptr;
#else
    return GetEnvVar( "TRACY_WEBSOCKET_ORIGINS" );
#endif
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

// SHA-1, see RFC 3174.
constexpr size_t WsSha1DigestSize = 20;
constexpr size_t WsSha1BlockSize = 64;
constexpr size_t WsSha1WordsPerBlock = WsSha1BlockSize / 4;
constexpr size_t WsSha1Rounds = 80;
// Rounds that use the same function and constant.
constexpr size_t WsSha1RoundsPerStage = 20;
// The input is followed by a 0x80 byte and by its length in bits, as a 64-bit number.
constexpr uint8_t WsSha1EndMark = 0x80;
constexpr size_t WsSha1LenSize = 8;
// Longest input that fits in two blocks.
constexpr size_t WsSha1MaxInput = 2 * WsSha1BlockSize - WsSha1LenSize - 1;
constexpr uint32_t WsSha1Init[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
// One constant for each stage.
constexpr uint32_t WsSha1K[4] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

static inline uint32_t WsRotl( uint32_t x, int n )
{
    return ( x << n ) | ( x >> ( 32 - n ) );
}

static void WsSha1( const uint8_t* data, size_t len, uint8_t out[WsSha1DigestSize] )
{
    TRACY_ASSERT( len <= WsSha1MaxInput );
    uint8_t msg[2 * WsSha1BlockSize] = {};
    memcpy( msg, data, len );
    msg[len] = WsSha1EndMark;
    const size_t blocks = len + WsSha1LenSize + 1 <= WsSha1BlockSize ? 1 : 2;
    const uint64_t bits = uint64_t( len ) * 8;
    for( size_t i=0; i<WsSha1LenSize; i++ ) msg[blocks*WsSha1BlockSize - 1 - i] = uint8_t( bits >> ( 8 * i ) );

    uint32_t h[5];
    memcpy( h, WsSha1Init, sizeof( h ) );
    for( size_t b=0; b<blocks; b++ )
    {
        uint32_t w[WsSha1Rounds];
        for( size_t i=0; i<WsSha1WordsPerBlock; i++ )
        {
            const auto m = msg + b*WsSha1BlockSize + i*4;
            w[i] = ( uint32_t( m[0] ) << 24 ) | ( uint32_t( m[1] ) << 16 ) | ( uint32_t( m[2] ) << 8 ) | m[3];
        }
        for( size_t i=WsSha1WordsPerBlock; i<WsSha1Rounds; i++ )
        {
            w[i] = WsRotl( w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1 );
        }
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
        for( size_t i=0; i<WsSha1Rounds; i++ )
        {
            const auto stage = i / WsSha1RoundsPerStage;
            uint32_t f;
            if( stage == 0 )      f = ( bb & c ) | ( ~bb & d );
            else if( stage == 2 ) f = ( bb & c ) | ( bb & d ) | ( c & d );
            else                  f = bb ^ c ^ d;
            const uint32_t t = WsRotl( a, 5 ) + f + e + WsSha1K[stage] + w[i];
            e = d;
            d = c;
            c = WsRotl( bb, 30 );
            bb = a;
            a = t;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;
    }
    for( int i=0; i<5; i++ )
    {
        out[i*4+0] = uint8_t( h[i] >> 24 );
        out[i*4+1] = uint8_t( h[i] >> 16 );
        out[i*4+2] = uint8_t( h[i] >> 8 );
        out[i*4+3] = uint8_t( h[i] );
    }
}

// Each 3 bytes become 4 characters of 6 bits. The 20 bytes of a SHA-1 end with 2 bytes, which become 3 characters and a '='.
constexpr uint32_t WsBase64Mask = 63;
constexpr size_t WsBase64Full = WsSha1DigestSize - WsSha1DigestSize % 3;
// 28 characters and a NUL.
constexpr size_t WsAcceptSize = 29;

static void WsBase64Sha1( const uint8_t* in, char* out )
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int o = 0;
    for( size_t i=0; i<WsBase64Full; i+=3 )
    {
        const uint32_t v = ( uint32_t( in[i] ) << 16 ) | ( uint32_t( in[i+1] ) << 8 ) | in[i+2];
        out[o++] = tbl[( v >> 18 ) & WsBase64Mask];
        out[o++] = tbl[( v >> 12 ) & WsBase64Mask];
        out[o++] = tbl[( v >> 6 ) & WsBase64Mask];
        out[o++] = tbl[v & WsBase64Mask];
    }
    const uint32_t v = ( uint32_t( in[WsBase64Full] ) << 16 ) | ( uint32_t( in[WsBase64Full+1] ) << 8 );
    out[o++] = tbl[( v >> 18 ) & WsBase64Mask];
    out[o++] = tbl[( v >> 12 ) & WsBase64Mask];
    out[o++] = tbl[( v >> 6 ) & WsBase64Mask];
    out[o++] = '=';
    out[o] = 0;
}

// Finds a header value in an HTTP request. Name is lowercase.
static bool WsFindHeader( const char* req, size_t reqLen, const char* name, const char*& val, size_t& valLen )
{
    const auto nameLen = strlen( name );
    const auto end = req + reqLen;
    auto p = (const char*)memchr( req, '\n', reqLen );     // skip the request line
    while( p && p + 1 < end )
    {
        p++;
        auto eol = (const char*)memchr( p, '\n', end - p );
        if( !eol ) break;
        auto lineEnd = eol;
        if( lineEnd > p && lineEnd[-1] == '\r' ) lineEnd--;
        if( lineEnd == p ) break;
        if( size_t( lineEnd - p ) > nameLen && p[nameLen] == ':' && WsIEq( p, name, nameLen ) )
        {
            auto v = p + nameLen + 1;
            while( v < lineEnd && ( *v == ' ' || *v == '\t' ) ) v++;
            auto ve = lineEnd;
            while( ve > v && ( ve[-1] == ' ' || ve[-1] == '\t' ) ) ve--;
            val = v;
            valLen = ve - v;
            return true;
        }
        p = eol;
    }
    return false;
}

// Case insensitive token search in a comma separated header value.
static bool WsHasToken( const char* val, size_t len, const char* token )
{
    const auto tl = strlen( token );
    size_t i = 0;
    while( i < len )
    {
        while( i < len && ( val[i] == ',' || val[i] == ' ' || val[i] == '\t' ) ) i++;
        const auto start = i;
        while( i < len && val[i] != ',' && val[i] != ' ' && val[i] != '\t' ) i++;
        if( i - start == tl && WsIEq( val + start, token, tl ) ) return true;
    }
    return false;
}

bool Socket::WsHandshake( int timeout )
{
    const auto sock = m_sock.load( std::memory_order_relaxed );
    char req[8192];
    size_t len = 0;
    size_t hdrEnd = 0;
    for( int left=timeout; left>0 && !hdrEnd; left-=100 )
    {
        struct pollfd fd;
        fd.fd = (socket_t)sock;
        fd.events = POLLIN;
        if( poll( &fd, 1, 100 ) <= 0 ) continue;
        const auto r = recv( sock, req + len, sizeof( req ) - len, 0 );
        if( r <= 0 ) return false;
        len += r;
        for( size_t j=0; j+3<len; j++ )
        {
            if( memcmp( req + j, "\r\n\r\n", 4 ) == 0 )
            {
                hdrEnd = j + 4;
                break;
            }
        }
        if( !hdrEnd && len == sizeof( req ) ) break;
    }

    static const char bad[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    static const char forbidden[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    if( !hdrEnd )
    {
        SendUnframed( bad, sizeof( bad ) - 1 );
        return false;
    }

    const char* val;
    size_t valLen;
    if( !WsFindHeader( req, hdrEnd, "upgrade", val, valLen ) || !WsHasToken( val, valLen, "websocket" ) ||
        !WsFindHeader( req, hdrEnd, "connection", val, valLen ) || !WsHasToken( val, valLen, "upgrade" ) ||
        !WsFindHeader( req, hdrEnd, "sec-websocket-version", val, valLen ) || valLen != 2 || memcmp( val, "13", 2 ) != 0 )
    {
        SendUnframed( bad, sizeof( bad ) - 1 );
        return false;
    }

    if( WsFindHeader( req, hdrEnd, "origin", val, valLen ) )
    {
#ifdef TRACY_WEBSOCKET_ORIGINS
        const char* def = TRACY_WEBSOCKET_ORIGINS;
#else
        const char* def = "";
#endif
        char envBuf[4096];
        const char* env = WsEnvOrigins( envBuf, sizeof( envBuf ) );
        if( !WebSocketOriginAllowed( val, valLen, def ) && !( env && WebSocketOriginAllowed( val, valLen, env ) ) )
        {
            SendUnframed( forbidden, sizeof( forbidden ) - 1 );
            return false;
        }
    }

    if( !WsFindHeader( req, hdrEnd, "sec-websocket-key", val, valLen ) || valLen != 24 )
    {
        SendUnframed( bad, sizeof( bad ) - 1 );
        return false;
    }
    uint8_t keyGuid[60];
    memcpy( keyGuid, val, 24 );
    memcpy( keyGuid + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36 );
    uint8_t digest[20];
    WsSha1( keyGuid, sizeof( keyGuid ), digest );
    char accept[32];
    WsBase64Sha1( digest, accept );

    bool binary = false;
    if( WsFindHeader( req, hdrEnd, "sec-websocket-protocol", val, valLen ) ) binary = WsHasToken( val, valLen, "binary" );

    char resp[256];
    const auto rl = snprintf( resp, sizeof( resp ),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s\r\n",
        accept, binary ? "Sec-WebSocket-Protocol: binary\r\n" : "" );
    return SendUnframed( resp, rl ) != -1;
}

}

#endif
