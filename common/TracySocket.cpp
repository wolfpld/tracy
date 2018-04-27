#include <assert.h>
#include <new>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "TracyAlloc.hpp"
#include "TracySocket.hpp"

#ifdef _MSC_VER
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <unistd.h>
#endif

#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif

namespace tracy
{

#ifdef _MSC_VER
struct __wsinit
{
    __wsinit()
    {
        WSADATA wsaData;
        if( WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != 0 )
        {
            fprintf( stderr, "Cannot init winsock.\n" );
            exit( 1 );
        }
    }
};

static __wsinit InitWinSock()
{
    static __wsinit init;
    return init;
}
#endif

Socket::Socket()
    : m_sock( -1 )
{
#ifdef _MSC_VER
    InitWinSock();
#endif
}

Socket::Socket( int sock )
    : m_sock( sock )
{
}

Socket::~Socket()
{
    if( m_sock != -1 )
    {
        Close();
    }
}

bool Socket::Connect( const char* addr, const char* port )
{
    assert( m_sock == -1 );

    struct addrinfo hints;
    struct addrinfo *res, *ptr;

    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if( getaddrinfo( addr, port, &hints, &res ) != 0 ) return false;
    int sock;
    for( ptr = res; ptr; ptr = ptr->ai_next )
    {
        if( ( sock = socket( ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol ) ) == -1 ) continue;
#if defined __APPLE__
        int val = 1;
        setsockopt( m_sock, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof( val ) );
#endif
        if( connect( sock, ptr->ai_addr, ptr->ai_addrlen ) == -1 )
        {
#ifdef _MSC_VER
            closesocket( sock );
#else
            close( sock );
#endif
            continue;
        }
        break;
    }
    freeaddrinfo( res );
    if( !ptr ) return false;

    m_sock = sock;
    return true;
}

void Socket::Close()
{
    assert( m_sock != -1 );
#ifdef _MSC_VER
    closesocket( m_sock );
#else
    close( m_sock );
#endif
    m_sock = -1;
}

int Socket::Send( const void* _buf, int len )
{
    auto buf = (const char*)_buf;
    assert( m_sock != -1 );
    auto start = buf;
    while( len > 0 )
    {
        auto ret = send( m_sock, buf, len, MSG_NOSIGNAL );
        if( ret == -1 ) return -1;
        len -= ret;
        buf += ret;
    }
    return int( buf - start );
}

int Socket::Recv( void* _buf, int len, const timeval* tv )
{
    auto buf = (char*)_buf;

    fd_set fds;
    FD_ZERO( &fds );
    FD_SET( m_sock, &fds );

#ifndef _WIN32
    timeval _tv = *tv;
    select( m_sock+1, &fds, nullptr, nullptr, &_tv );
#else
    select( m_sock+1, &fds, nullptr, nullptr, tv );
#endif
    if( FD_ISSET( m_sock, &fds ) )
    {
        return recv( m_sock, buf, len, 0 );
    }
    else
    {
        return -1;
    }
}

bool Socket::Read( void* _buf, int len, const timeval* tv, std::function<bool()> exitCb )
{
    auto buf = (char*)_buf;

    while( len > 0 )
    {
        if( exitCb() ) return false;
        const auto sz = Recv( buf, len, tv );
        switch( sz )
        {
        case 0:
            return false;
        case -1:
#ifdef _WIN32
        {
            auto err = WSAGetLastError();
            if( err == WSAECONNABORTED || err == WSAECONNRESET ) return false;
        }
#endif
            break;
        default:
            len -= sz;
            buf += sz;
            break;
        }
    }

    return true;
}

bool Socket::HasData()
{
    struct timeval tv;
    memset( &tv, 0, sizeof( tv ) );

    fd_set fds;
    FD_ZERO( &fds );
    FD_SET( m_sock, &fds );

    select( m_sock+1, &fds, nullptr, nullptr, &tv );
    return FD_ISSET( m_sock, &fds );
}


ListenSocket::ListenSocket()
    : m_sock( -1 )
{
#ifdef _MSC_VER
    InitWinSock();
#endif
}

ListenSocket::~ListenSocket()
{
}

bool ListenSocket::Listen( const char* port, int backlog )
{
    assert( m_sock == -1 );

    struct addrinfo* res;
    struct addrinfo hints;

    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if( getaddrinfo( nullptr, port, &hints, &res ) != 0 ) return false;

    m_sock = socket( res->ai_family, res->ai_socktype, res->ai_protocol );
#if defined _MSC_VER || defined __CYGWIN__
    unsigned long val = 0;
    setsockopt( m_sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&val, sizeof( val ) );
#else
    int val = 1;
    setsockopt( m_sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof( val ) );
#endif
    if( bind( m_sock, res->ai_addr, res->ai_addrlen ) == -1 ) return false;
    if( listen( m_sock, backlog ) == -1 ) return false;
    return true;
}

Socket* ListenSocket::Accept()
{
    struct sockaddr_storage remote;
    socklen_t sz = sizeof( remote );

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    fd_set fds;
    FD_ZERO( &fds );
    FD_SET( m_sock, &fds );

    select( m_sock+1, &fds, nullptr, nullptr, &tv );
    if( FD_ISSET( m_sock, &fds ) )
    {
        int sock = accept( m_sock, (sockaddr*)&remote, &sz);
#if defined __APPLE__
        int val = 1;
        setsockopt( sock, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof( val ) );
#endif
        if( sock == -1 )
        {
            return nullptr;
        }
        else
        {
            auto ptr = (Socket*)tracy_malloc( sizeof( Socket ) );
            new(ptr) Socket( sock );
            return ptr;
        }
    }
    else
    {
        return nullptr;
    }
}

void ListenSocket::Close()
{
    assert( m_sock != -1 );
#ifdef _MSC_VER
    closesocket( m_sock );
#else
    close( m_sock );
#endif
    m_sock = -1;
}

}
