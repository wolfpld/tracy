#ifndef __TRACYCOLOR_HPP__
#define __TRACYCOLOR_HPP__

#include <algorithm>
#include <stdint.h>

#include "../public/common/TracyForceInline.hpp"

namespace tracy
{

uint32_t GetHsvColor( uint64_t hue, int value );

template<int V = 25>
static tracy_force_inline uint32_t HighlightColor( uint32_t color )
{
    return 0xFF000000 |
        ( std::min<int>( 0xFF, ( ( ( color & 0x00FF0000 ) >> 16 ) + V ) ) << 16 ) |
        ( std::min<int>( 0xFF, ( ( ( color & 0x0000FF00 ) >> 8  ) + V ) ) << 8  ) |
        ( std::min<int>( 0xFF, ( ( ( color & 0x000000FF )       ) + V ) )       );
}

static tracy_force_inline uint32_t DarkenColor( uint32_t color )
{
    return 0xFF000000 |
        ( ( ( ( color & 0x00FF0000 ) >> 16 ) * 2 / 3 ) << 16 ) |
        ( ( ( ( color & 0x0000FF00 ) >> 8  ) * 2 / 3 ) << 8  ) |
        ( ( ( ( color & 0x000000FF )       ) * 2 / 3 )       );
}

static tracy_force_inline uint32_t DarkenColorMore( uint32_t color )
{
    return 0xFF000000 |
        ( ( ( ( color & 0x00FF0000 ) >> 16 ) * 1 / 4 ) << 16 ) |
        ( ( ( ( color & 0x0000FF00 ) >> 8  ) * 1 / 4 ) << 8  ) |
        ( ( ( ( color & 0x000000FF )       ) * 1 / 4 )       );
}

}

#endif
