#ifndef __TRACYSOCKET_HPP__
#define __TRACYSOCKET_HPP__

#include <atomic>
#include <stddef.h>
#include <stdint.h>

struct addrinfo;
struct sockaddr;

namespace tracy
{

#ifdef _WIN32
void InitWinSock();
#endif

#ifdef TRACY_WEBSOCKET_SUPPORT
constexpr int WsBaseHdrSize = 2;
constexpr int WsLen16Size = 2;
constexpr int WsLen64Size = 8;
// Size of the mask of a client frame.
constexpr int WsMaskSize = 4;
// Payload lengths up to this are in the 7-bit length field of the header.
constexpr int WsMaxLen7 = 125;
// Control frames can't have more payload than the 7-bit length field holds.
constexpr int WsMaxControlLen = WsMaxLen7;
// Headroom needed before a buffer passed to Socket::SendFramed.
// A frame sent by the server is not masked.
constexpr int WebSocketMaxHeaderSize = WsBaseHdrSize + WsLen64Size;
// Base header, 64-bit length and mask.
constexpr int WsMaxClientHdrSize = WsBaseHdrSize + WsLen64Size + WsMaskSize;
#endif

class Socket
{
public:
    Socket();
    // A socket accepted by ListenSocket. A WebSocket client is detected on the first read.
    Socket( int sock );
    ~Socket();

    bool Connect( const char* addr, uint16_t port );
    void Close();

    int Send( const void* buf, int len );
#ifdef TRACY_WEBSOCKET_SUPPORT
    // buf has WebSocketMaxHeaderSize bytes of room, followed by len bytes of data.
    int SendFramed( void* buf, int len );
#endif
    int GetSendBufSize();

    int ReadUpTo( void* buf, int len );
    bool Read( void* buf, int len, int timeout );

    template<typename ShouldExit>
    bool Read( void* buf, int len, int timeout, ShouldExit exitCb )
    {
        auto cbuf = (char*)buf;
        while( len > 0 )
        {
            if( exitCb() ) return false;
            if( !ReadImpl( cbuf, len, timeout ) ) return false;
        }
        return true;
    }

    template<typename ShouldExit>
    int ReadUpTo( void* buf, int len, int timeout, ShouldExit exitCb )
    {
        auto cbuf = (char*)buf;
        int rd = 0;
        while( len > 0 )
        {
            if( exitCb() ) return rd;
            char* p = cbuf;
            int l = len;
            if( !ReadImpl( p, l, timeout ) ) return rd;
            const auto step = len - l;
            rd += step;
            cbuf += step;
            len -= step;
        }
        return rd;
    }

    bool ReadRaw( void* buf, int len, int timeout );
    bool HasData();
    bool IsValid() const;
    bool IsConnecting() const;

    Socket( const Socket& ) = delete;
    Socket( Socket&& ) = delete;
    Socket& operator=( const Socket& ) = delete;
    Socket& operator=( Socket&& ) = delete;

private:
    int RecvBuffered( void* buf, int len, int timeout );
    int Recv( void* buf, int len, int timeout );
    // RecvUnframed and SendUnframed use the socket directly, with no WebSocket framing. The other functions (ReadRaw included) go through Recv and Send.
    int RecvUnframed( void* buf, int len, int timeout );
    int SendUnframed( const void* buf, int len );

#ifdef TRACY_WEBSOCKET_SUPPORT
    enum WsState { WsNone, WsDetect, WsActive };

    // The WebSocket frame being read.
    struct WsFrame
    {
        // True once the header is read, until the whole payload is.
        bool hdrDone = false;
        uint8_t hdrLen = 0;
        uint8_t opcode = 0;
        uint8_t maskOff = 0;
        uint8_t ctlLen = 0;
        uint8_t hdr[WsMaxClientHdrSize];
        uint8_t mask[WsMaskSize];
        uint8_t ctl[WsMaxControlLen];
        uint64_t remain = 0;
        // True once the connection is closed or broken. Every read then reports it.
        bool closed = false;
        // True between the first frame of a message and its last one.
        bool fragmented = false;

        // A data frame with payload left to read.
        bool Pending() const { return hdrDone && opcode < 8 && remain > 0; }
    };

    int WsDetectProtocol( int timeout );
    bool WsHandshake( int timeout );
    int WsRecv( void* buf, int len, int timeout );
    int WsFrameStep( int timeout );
    bool WsHasData();
    int WsSend( const void* buf, int len );
    void WsSendControl( uint8_t opcode, const uint8_t* data, int len );
    void WsClose( uint16_t code );
#endif

    bool ReadImpl( char*& buf, int& len, int timeout );

    char* m_buf;
    char* m_bufPtr;
    std::atomic<int> m_sock;
    int m_bufLeft;

    struct addrinfo *m_res;
    struct addrinfo *m_ptr;
    int m_connSock;

#ifdef TRACY_WEBSOCKET_SUPPORT
    WsState m_wsState = WsNone;
    WsFrame m_wsFrame;
#endif
};

class ListenSocket
{
public:
    ListenSocket();
    ~ListenSocket();

    bool Listen( uint16_t port, int backlog );
    Socket* Accept();
    void Close();
    void Adopt( int fd );
    uint16_t LocalPort() const;

    ListenSocket( const ListenSocket& ) = delete;
    ListenSocket( ListenSocket&& ) = delete;
    ListenSocket& operator=( const ListenSocket& ) = delete;
    ListenSocket& operator=( ListenSocket&& ) = delete;

private:
    int m_sock;
};

class UdpBroadcast
{
public:
    UdpBroadcast();
    ~UdpBroadcast();

    bool Open( const char* addr, uint16_t port );
    void Close();

    int Send( uint16_t port, const void* data, int len );

    UdpBroadcast( const UdpBroadcast& ) = delete;
    UdpBroadcast( UdpBroadcast&& ) = delete;
    UdpBroadcast& operator=( const UdpBroadcast& ) = delete;
    UdpBroadcast& operator=( UdpBroadcast&& ) = delete;

private:
    int m_sock;
    uint32_t m_addr;
};

class IpAddress
{
public:
    IpAddress();
    ~IpAddress();

    void Set( const struct sockaddr& addr );

    uint32_t GetNumber() const { return m_number; }
    const char* GetText() const { return m_text; }

    IpAddress( const IpAddress& ) = delete;
    IpAddress( IpAddress&& ) = delete;
    IpAddress& operator=( const IpAddress& ) = delete;
    IpAddress& operator=( IpAddress&& ) = delete;

private:
    uint32_t m_number;
    char m_text[17];
};

class UdpListen
{
public:
    UdpListen();
    ~UdpListen();

    bool Listen( uint16_t port );
    void Close();

    const char* Read( size_t& len, IpAddress& addr, int timeout );

    UdpListen( const UdpListen& ) = delete;
    UdpListen( UdpListen&& ) = delete;
    UdpListen& operator=( const UdpListen& ) = delete;
    UdpListen& operator=( UdpListen&& ) = delete;

private:
    int m_sock;
};

}

#endif
