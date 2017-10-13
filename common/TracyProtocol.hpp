#ifndef __TRACYPROTOCOL_HPP__
#define __TRACYPROTOCOL_HPP__

#include <limits>
#include <stdint.h>

#include "../common/tracy_lz4.hpp"

namespace tracy
{

using lz4sz_t = uint16_t;

enum { TargetFrameSize = 64000 };
enum { LZ4Size = LZ4_COMPRESSBOUND( TargetFrameSize ) };
static_assert( LZ4Size <= std::numeric_limits<lz4sz_t>::max(), "LZ4Size greater than lz4sz_t" );
static_assert( TargetFrameSize * 2 >= 64 * 1024, "Not enough space for LZ4 stream buffer" );

enum ServerQuery : uint8_t
{
    ServerQueryString,
    ServerQueryThreadString,
    ServerQueryCustomString,
    ServerQuerySourceLocation,
    ServerQueryPlotName,
};

enum { WelcomeMessageProgramNameSize = 64 };

#pragma pack( 1 )
struct WelcomeMessage
{
    uint8_t lz4;
    double timerMul;
    uint64_t timeBegin;
    uint64_t delay;
    uint64_t resolution;
    uint64_t epoch;
    char programName[WelcomeMessageProgramNameSize];
};
#pragma pack()

enum { WelcomeMessageSize = sizeof( WelcomeMessage ) };

}

#endif
