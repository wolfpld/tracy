#ifndef __TRACYFILEHEADER_HPP__
#define __TRACYFILEHEADER_HPP__

#include "../common/TracyForceInline.hpp"

namespace tracy
{

static const char Lz4Header[4]  = { 't', 'l', 'Z', 4 };
static const char ZstdHeader[4] = { 't', 'Z', 's', 't' };

static constexpr tracy_force_inline int FileVersion( uint8_t h5, uint8_t h6, uint8_t h7 )
{
    return ( h5 << 16 ) | ( h6 << 8 ) | h7;
}

}

#endif
