#ifndef __TRACYPROTOCOL_HPP__
#define __TRACYPROTOCOL_HPP__

#include <limits>
#include <stdint.h>

#include "../common/tracy_lz4.hpp"

namespace tracy
{

enum { TargetFrameSize = 64000 };
enum { LZ4Size = LZ4_COMPRESSBOUND( TargetFrameSize ) };
static_assert( LZ4Size <= std::numeric_limits<uint16_t>::max(), "LZ4Size greater than uint16_t" );

}

#endif
