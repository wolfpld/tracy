#ifndef __TRACYSOCKET_HPP__
#define __TRACYSOCKET_HPP__

#include <functional>

struct timeval;

namespace tracy
{

class Socket
{
    enum { BufSize = 128 * 1024 };

public:
    Socket();
    Socket( int sock );
    ~Socket();

    bool Connect( const char* addr, const char* port );
    void Close();

    int Send( const void* buf, int len );

    bool Read( void* buf, int len, const timeval* tv, std::function<bool()> exitCb );
    bool HasData();

    Socket( const Socket& ) = delete;
    Socket( Socket&& ) = delete;
    Socket& operator=( const Socket& ) = delete;
    Socket& operator=( Socket&& ) = delete;

private:
    int RecvBuffered( void* buf, int len, const timeval* tv );
    int Recv( void* buf, int len, const timeval* tv );

    int m_sock;

    char* m_buf;
    char* m_bufPtr;
    int m_bufLeft;
};

class ListenSocket
{
public:
    ListenSocket();
    ~ListenSocket();

    bool Listen( const char* port, int backlog );
    Socket* Accept();
    void Close();

    ListenSocket( const ListenSocket& ) = delete;
    ListenSocket( ListenSocket&& ) = delete;
    ListenSocket& operator=( const ListenSocket& ) = delete;
    ListenSocket& operator=( ListenSocket&& ) = delete;

private:
    int m_sock;
};

}

#endif
