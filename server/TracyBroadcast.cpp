#include "TracyBroadcast.hpp"
#include <cassert>
#include <cstring>

namespace tracy
{

std::optional<BroadcastMessage> ParseBroadcastMessage( const char* msg, size_t msgLen )
{
    if( msgLen < sizeof( uint16_t ) ) return std::nullopt;

    uint16_t broadcastVersion;
    memcpy( &broadcastVersion, msg, sizeof( uint16_t ) );
    if( broadcastVersion > tracy::BroadcastVersion ) return std::nullopt;

    switch( broadcastVersion )
    {
    case 3:
    {
        if( msgLen > sizeof( tracy::BroadcastMessage ) ) return std::nullopt;
        tracy::BroadcastMessage bm;
        memcpy( &bm, msg, msgLen );
        return bm;
    }
    case 2:
    {
        if( msgLen > sizeof( tracy::BroadcastMessage_v2 ) ) return std::nullopt;
        tracy::BroadcastMessage_v2 bm;
        memcpy( &bm, msg, msgLen );
        tracy::BroadcastMessage out;
        out.broadcastVersion = broadcastVersion;
        out.protocolVersion = bm.protocolVersion;
        out.activeTime = bm.activeTime;
        out.listenPort = bm.listenPort;
        strcpy( out.programName, bm.programName );
        out.pid = 0;
        return out;
    }
    case 1:
    {
        if( msgLen > sizeof( tracy::BroadcastMessage_v1 ) ) return std::nullopt;
        tracy::BroadcastMessage_v1 bm;
        memcpy( &bm, msg, msgLen );
        tracy::BroadcastMessage out;
        out.broadcastVersion = broadcastVersion;
        out.protocolVersion = bm.protocolVersion;
        out.activeTime = bm.activeTime;
        out.listenPort = bm.listenPort;
        strcpy( out.programName, bm.programName );
        out.pid = 0;
        return out;
    }
    case 0:
    {
        if( msgLen > sizeof( tracy::BroadcastMessage_v0 ) ) return std::nullopt;
        tracy::BroadcastMessage_v0 bm;
        memcpy( &bm, msg, msgLen );
        tracy::BroadcastMessage out;
        out.broadcastVersion = broadcastVersion;
        out.protocolVersion = bm.protocolVersion;
        out.activeTime = bm.activeTime;
        out.listenPort = 8086;
        strcpy( out.programName, bm.programName );
        out.pid = 0;
        return out;
    }
    default:
        assert( false );
        return std::nullopt;
    }
}

uint64_t ClientUniqueID( const IpAddress& addr, uint16_t port )
{
    return uint64_t( addr.GetNumber() ) | ( uint64_t( port ) << 32 );
}

}
