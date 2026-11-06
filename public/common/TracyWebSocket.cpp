#ifdef TRACY_WEBSOCKET_SUPPORT

#include <chrono>
#include <errno.h>
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

// Fixed GUID from RFC 6455 section 1.3. It is appended to the client key to build the accept key.
constexpr char WsGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr size_t WsGuidLen = sizeof( WsGuid ) - 1;
// Sec-WebSocket-Key is 16 random bytes, base64 encoded.
constexpr size_t WsKeyLen = 24;

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

enum WsOpcode : uint8_t
{
    WsOpContinuation = 0,
    WsOpBinary = 2,
    WsOpClose = 8,
    WsOpPing = 9,
    WsOpPong = 10
};

constexpr uint8_t WsFin = 0x80;
constexpr uint8_t WsMaskBit = 0x80;
constexpr uint8_t WsOpcodeMask = 0x0f;
// The RSV1-3 bits, used by extensions.
constexpr uint8_t WsRsvMask = 0x70;
constexpr uint8_t WsLenMask = 0x7f;
// WsLen16 and WsLen64 say that the length follows in 2 or 8 bytes.
constexpr uint8_t WsLen16 = 126;
constexpr uint8_t WsLen64 = 127;
constexpr int WsMaxLen16 = 65535;
// Payloads up to this size are sent with their header in one buffer, on the stack.
constexpr int WsSendCopyMax = 1024;
// Frames without payload data read by one call to WsHasData or WsRecv.
constexpr int WsMaxControlPerPoll = 16;
// A Close frame starts with a 16-bit status code.
constexpr int WsCloseCodeSize = 2;
constexpr uint16_t WsCloseProtocolError = 1002;

static int WsMakeHeader( uint8_t* h, uint64_t len )
{
    h[0] = WsFin | WsOpBinary;
    if( len <= WsMaxLen7 )
    {
        h[1] = uint8_t( len );
        return WsBaseHdrSize;
    }
    if( len <= WsMaxLen16 )
    {
        h[1] = WsLen16;
        h[2] = uint8_t( len >> 8 );
        h[3] = uint8_t( len );
        return WsBaseHdrSize + WsLen16Size;
    }
    h[1] = WsLen64;
    for( int i=0; i<WsLen64Size; i++ ) h[WsBaseHdrSize+i] = uint8_t( len >> ( 56 - 8 * i ) );
    return WsBaseHdrSize + WsLen64Size;
}

int Socket::WsDetectProtocol( int timeout )
{
    const auto sock = m_sock.load( std::memory_order_relaxed );
    struct pollfd fd;
    fd.fd = (socket_t)sock;
    fd.events = POLLIN;
    if( poll( &fd, 1, timeout ) <= 0 ) return -1;

    // One byte tells the two apart: the Tracy handshake starts with 'T', an HTTP request with 'G'.
    char c;
    const auto n = recv( sock, &c, 1, MSG_PEEK );
    if( n == 0 ) return 0;
    if( n < 0 ) return -1;
    if( c != 'G' )
    {
        m_wsState = WsNone;
        return 1;
    }
    if( !WsHandshake( timeout ) ) return 0;
    m_wsState = WsActive;
    return 1;
}

bool Socket::WsHandshake( int timeout )
{
    const auto sock = m_sock.load( std::memory_order_relaxed );
    // A browser handshake is a few hundred bytes to 2 KB. 16 KB is the cap for the stack buffer, a bigger request gets a 431.
    char req[16384];
    size_t len = 0;
    size_t hdrEnd = 0;
    // A negative timeout waits forever.
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds( timeout < 0 ? 0 : timeout );
    while( !hdrEnd && len < sizeof( req ) )
    {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>( end - std::chrono::steady_clock::now() ).count();
        if( timeout < 0 ) left = -1;
        else if( left < 0 ) left = 0;
        struct pollfd fd;
        fd.fd = (socket_t)sock;
        fd.events = POLLIN;
        const auto pr = poll( &fd, 1, (int)left );
        if( pr == 0 ) break;
        if( pr < 0 )
        {
#ifndef _WIN32
            if( errno == EINTR && left != 0 ) continue;
#endif
            break;
        }
        // The client waits for the response before it sends frames, so only the request is read here.
        const auto r = recv( sock, req + len, int( sizeof( req ) - len ), 0 );
        if( r <= 0 ) return false;
        const auto prev = len;
        len += r;
        for( size_t j = prev > 3 ? prev - 3 : 0; j+3<len; j++ )
        {
            if( memcmp( req + j, "\r\n\r\n", 4 ) == 0 )
            {
                hdrEnd = j + 4;
                break;
            }
        }
    }

    static const char bad[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    static const char tooLarge[] = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    static const char forbidden[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    if( !hdrEnd )
    {
        if( len == sizeof( req ) ) SendUnframed( tooLarge, sizeof( tooLarge ) - 1 );
        else SendUnframed( bad, sizeof( bad ) - 1 );
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

    if( !WsFindHeader( req, hdrEnd, "sec-websocket-key", val, valLen ) || valLen != WsKeyLen )
    {
        SendUnframed( bad, sizeof( bad ) - 1 );
        return false;
    }
    uint8_t keyGuid[WsKeyLen + WsGuidLen];
    memcpy( keyGuid, val, WsKeyLen );
    memcpy( keyGuid + WsKeyLen, WsGuid, WsGuidLen );
    uint8_t digest[WsSha1DigestSize];
    WsSha1( keyGuid, sizeof( keyGuid ), digest );
    char accept[WsAcceptSize];
    WsBase64Sha1( digest, accept );

    bool binary = false;
    if( WsFindHeader( req, hdrEnd, "sec-websocket-protocol", val, valLen ) ) binary = WsHasToken( val, valLen, "binary" );

    char resp[256];
    const auto rl = snprintf( resp, sizeof( resp ),
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s\r\n",
        accept, binary ? "Sec-WebSocket-Protocol: binary\r\n" : "" );
    return SendUnframed( resp, rl ) != -1;
}

int Socket::WsRecv( void* _buf, int len, int timeout )
{
    auto& f = m_wsFrame;
    auto buf = (uint8_t*)_buf;
    for( int steps=0; ; steps++ )
    {
        if( f.Pending() )
        {
            const int n = f.remain < uint64_t( len ) ? int( f.remain ) : len;
            const auto r = RecvUnframed( buf, n, timeout );
            if( r <= 0 ) return r;
            for( int i=0; i<r; i++ ) buf[i] ^= f.mask[( f.maskOff + i ) & 3];
            f.maskOff = uint8_t( f.maskOff + r );
            f.remain -= r;
            if( f.remain == 0 ) f.hdrDone = false;
            return r;
        }
        // A peer sending only control frames must not keep the caller from checking if it should exit.
        // The read gives up even if its timeout is not over, which is fine for such a peer. Without a timeout it can't be interrupted anyway.
        if( steps == WsMaxControlPerPoll && timeout >= 0 ) return -1;
        const auto r = WsFrameStep( timeout );
        if( r <= 0 ) return r;
    }
}

// Reads a frame header, and the whole frame if it is a control frame.
// Returns 1 on progress, 0 when the connection is closed or broken, -1 when no data is available yet.
int Socket::WsFrameStep( int timeout )
{
    auto& f = m_wsFrame;
    if( f.closed ) return 0;
    if( !f.hdrDone )
    {
        for(;;)
        {
            // A masked frame has at least this much header. A shorter read is fine, the size is worked out again below.
            int need = WsBaseHdrSize + WsMaskSize;
            if( f.hdrLen >= WsBaseHdrSize )
            {
                const auto l7 = f.hdr[1] & WsLenMask;
                need = WsBaseHdrSize + ( l7 == WsLen16 ? WsLen16Size : l7 == WsLen64 ? WsLen64Size : 0 ) + ( ( f.hdr[1] & WsMaskBit ) ? WsMaskSize : 0 );
            }
            if( f.hdrLen >= need ) break;
            const auto r = RecvUnframed( f.hdr + f.hdrLen, need - f.hdrLen, timeout );
            if( r <= 0 ) return r;
            f.hdrLen = uint8_t( f.hdrLen + r );
        }

        // Client frames must be masked.
        if( !( f.hdr[1] & WsMaskBit ) )
        {
            WsClose( WsCloseProtocolError );
            return 0;
        }
        f.opcode = f.hdr[0] & WsOpcodeMask;
        const auto l7 = f.hdr[1] & WsLenMask;
        uint64_t plen;
        int off = WsBaseHdrSize;
        if( l7 == WsLen16 )
        {
            plen = ( uint64_t( f.hdr[2] ) << 8 ) | f.hdr[3];
            off = WsBaseHdrSize + WsLen16Size;
        }
        else if( l7 == WsLen64 )
        {
            plen = 0;
            for( int i=0; i<WsLen64Size; i++ ) plen = ( plen << 8 ) | f.hdr[WsBaseHdrSize+i];
            off = WsBaseHdrSize + WsLen64Size;
        }
        else
        {
            plen = l7;
        }
        // No extension is negotiated. A length must use the fewest bytes, and a 64-bit one can't have its top bit set.
        const bool badLen = ( l7 == WsLen16 && plen <= WsMaxLen7 ) || ( l7 == WsLen64 && ( plen <= uint64_t( WsMaxLen16 ) || ( plen >> 63 ) != 0 ) );
        if( ( f.hdr[0] & WsRsvMask ) || badLen )
        {
            WsClose( WsCloseProtocolError );
            return 0;
        }
        memcpy( f.mask, f.hdr + off, WsMaskSize );
        f.maskOff = 0;
        f.ctlLen = 0;
        f.remain = plen;
        const bool fin = ( f.hdr[0] & WsFin ) != 0;
        f.hdrLen = 0;

        if( f.opcode >= 8 )
        {
            if( plen > WsMaxControlLen || !fin )
            {
                WsClose( WsCloseProtocolError );
                return 0;
            }
        }
        else if( f.opcode == WsOpBinary ? f.fragmented : ( f.opcode != WsOpContinuation || !f.fragmented ) )
        {
            // Text and reserved opcodes, and a data frame that doesn't fit in the message sequence.

            WsClose( WsCloseProtocolError );
            return 0;
        }
        f.hdrDone = true;
        if( f.opcode < 8 )
        {
            f.fragmented = !fin;
            if( plen == 0 ) f.hdrDone = false;
            return 1;
        }
    }

    // Control frame payload.
    while( f.remain > 0 )
    {
        const auto r = RecvUnframed( f.ctl + f.ctlLen, int( f.remain ), timeout );
        if( r <= 0 ) return r;
        for( int i=0; i<r; i++ ) f.ctl[f.ctlLen+i] ^= f.mask[( f.maskOff + i ) & 3];
        f.maskOff = uint8_t( f.maskOff + r );
        f.ctlLen = uint8_t( f.ctlLen + r );
        f.remain -= r;
    }
    f.hdrDone = false;
    switch( f.opcode )
    {
    case WsOpClose:
        WsSendControl( WsOpClose, f.ctl, f.ctlLen >= WsCloseCodeSize ? WsCloseCodeSize : 0 );
        f.closed = true;
        return 0;
    case WsOpPing:
        WsSendControl( WsOpPong, f.ctl, f.ctlLen );
        return 1;
    case WsOpPong:
        return 1;
    default:
        WsClose( WsCloseProtocolError );
        return 0;
    }
}

bool Socket::WsHasData()
{
    if( m_wsFrame.closed ) return true;

    // A broken connection counts as having data, as with a plain socket, so that the next read reports it.
    struct pollfd fd;
    fd.fd = (socket_t)m_sock.load( std::memory_order_relaxed );
    fd.events = POLLIN;
    const auto pr = poll( &fd, 1, 0 );
    if( pr > 0 && ( fd.revents & ( POLLERR | POLLHUP ) ) ) return true;
    if( pr <= 0 ) return m_wsFrame.Pending();

    // Consume control frames, report only when payload data is pending (or the connection is gone).
    // The number of frames is limited, or a peer sending nothing else would keep the caller from checking if it
    // should exit. The rest is read on the next call.
    for( int i=0; i<WsMaxControlPerPoll; i++ )
    {
        if( m_wsFrame.Pending() ) return true;
        const auto r = WsFrameStep( 0 );
        if( r == 0 ) return true;
        if( r < 0 ) return false;
    }
    return m_wsFrame.Pending();
}

// Called from the receive path. Only the profiler thread uses the socket, so this can't land between the parts of a send.
void Socket::WsSendControl( uint8_t opcode, const uint8_t* data, int len )
{
    uint8_t frame[WsBaseHdrSize+WsMaxControlLen];
    frame[0] = WsFin | opcode;
    frame[1] = uint8_t( len );
    memcpy( frame + WsBaseHdrSize, data, len );
    SendUnframed( frame, WsBaseHdrSize + len );
}

// Sends a Close frame with the status code. Every later read reports that the connection is closed.
void Socket::WsClose( uint16_t code )
{
    const uint8_t payload[WsCloseCodeSize] = { uint8_t( code >> 8 ), uint8_t( code ) };
    WsSendControl( WsOpClose, payload, WsCloseCodeSize );
    m_wsFrame.closed = true;
}

int Socket::WsSend( const void* buf, int len )
{
    uint8_t hdr[WebSocketMaxHeaderSize];
    const auto hl = WsMakeHeader( hdr, len );
    if( len <= WsSendCopyMax )
    {
        uint8_t tmp[WebSocketMaxHeaderSize + WsSendCopyMax];
        memcpy( tmp, hdr, hl );
        memcpy( tmp + hl, buf, len );
        return SendUnframed( tmp, hl + len ) == -1 ? -1 : len;
    }
    if( SendUnframed( hdr, hl ) == -1 ) return -1;
    return SendUnframed( buf, len );
}

int Socket::SendFramed( void* buf, int len )
{
    if( m_wsState == WsDetect ) return -1;
    auto data = (char*)buf + WebSocketMaxHeaderSize;
    if( m_wsState != WsActive ) return SendUnframed( data, len );
    uint8_t hdr[WebSocketMaxHeaderSize];
    const auto hl = WsMakeHeader( hdr, len );
    auto start = data - hl;
    memcpy( start, hdr, hl );
    return SendUnframed( start, hl + len ) == -1 ? -1 : len;
}

}

#endif
