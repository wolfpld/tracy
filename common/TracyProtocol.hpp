#ifndef __TRACYPROTOCOL_HPP__
#define __TRACYPROTOCOL_HPP__

#include <limits>
#include <stdint.h>

namespace tracy
{

constexpr unsigned Lz4CompressBound( unsigned isize ) { return isize + ( isize / 255 ) + 16; }

enum : uint32_t { ProtocolVersion = 25 };
enum : uint32_t { BroadcastVersion = 0 };

using lz4sz_t = uint32_t;

enum { TargetFrameSize = 256 * 1024 };
enum { LZ4Size = Lz4CompressBound( TargetFrameSize ) };
static_assert( LZ4Size <= std::numeric_limits<lz4sz_t>::max(), "LZ4Size greater than lz4sz_t" );
static_assert( TargetFrameSize * 2 >= 64 * 1024, "Not enough space for LZ4 stream buffer" );

enum { HandshakeShibbolethSize = 8 };
static const char HandshakeShibboleth[HandshakeShibbolethSize] = { 'T', 'r', 'a', 'c', 'y', 'P', 'r', 'f' };

enum HandshakeStatus : uint8_t
{
    HandshakePending,
    HandshakeWelcome,
    HandshakeProtocolMismatch,
    HandshakeNotAvailable,
    HandshakeDropped
};

enum { WelcomeMessageProgramNameSize = 64 };
enum { WelcomeMessageHostInfoSize = 1024 };

#pragma pack( 1 )

enum ServerQuery : uint8_t
{
    ServerQueryTerminate,
    ServerQueryString,
    ServerQueryThreadString,
    ServerQuerySourceLocation,
    ServerQueryPlotName,
    ServerQueryCallstackFrame,
    ServerQueryFrameName,
    ServerQueryDisconnect,
    ServerQueryExternalName,
    ServerQueryParameter
};

struct ServerQueryPacket
{
    ServerQuery type;
    uint64_t ptr;
};

enum { ServerQueryPacketSize = sizeof( ServerQueryPacket ) };


struct WelcomeMessage
{
    double timerMul;
    int64_t initBegin;
    int64_t initEnd;
    uint64_t delay;
    uint64_t resolution;
    uint64_t epoch;
    uint64_t pid;
    uint8_t onDemand;
    uint8_t isApple;
    char programName[WelcomeMessageProgramNameSize];
    char hostInfo[WelcomeMessageHostInfoSize];
};

enum { WelcomeMessageSize = sizeof( WelcomeMessage ) };


struct OnDemandPayloadMessage
{
    uint64_t frames;
    uint64_t currentTime;
};

enum { OnDemandPayloadMessageSize = sizeof( OnDemandPayloadMessage ) };


struct BroadcastMessage
{
    uint32_t broadcastVersion;
    uint32_t protocolVersion;
    uint32_t activeTime;        // in seconds
    char programName[WelcomeMessageProgramNameSize];
};

enum { BroadcastMessageSize = sizeof( BroadcastMessage ) };

#pragma pack()

}

#endif
