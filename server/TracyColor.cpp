#include <algorithm>

#include "TracyColor.hpp"

namespace tracy
{

uint32_t GetHsvColor( uint64_t hue, int value )
{
    const uint8_t h = ( hue * 11400714819323198485ull ) & 0xFF;
    const uint8_t s = 108;
    const uint8_t v = std::max( 96, 170 - value * 8 );

    const uint8_t reg = h / 43;
    const uint8_t rem = ( h - ( reg * 43 ) ) * 6;

    const uint8_t p = ( v * ( 255 - s ) ) >> 8;
    const uint8_t q = ( v * ( 255 - ( ( s * rem ) >> 8 ) ) ) >> 8;
    const uint8_t t = ( v * ( 255 - ( ( s * ( 255 - rem ) ) >> 8 ) ) ) >> 8;

    uint8_t r, g, b;

    switch( reg )
    {
    case 0:  r = v; g = t; b = p; break;
    case 1:  r = q; g = v; b = p; break;
    case 2:  r = p; g = v; b = t; break;
    case 3:  r = p; g = q; b = v; break;
    case 4:  r = t; g = p; b = v; break;
    default: r = v; g = p; b = q; break;
    }

    return 0xFF000000 | ( r << 16 ) | ( g << 8 ) | b;
}

}
