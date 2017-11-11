#ifndef __TRACYPOPCNT_HPP__
#define __TRACYPOPCNT_HPP__

#ifdef _MSC_VER
#  include <intrin.h>
#  define TracyCountBits __popcnt64
#else
static inline int TracyCountBits( uint64_t i )
{
    i = i - ( (i >> 1) & 0x5555555555555555 );
    i = ( i & 0x3333333333333333 ) + ( (i >> 2) & 0x3333333333333333 );
    i = ( (i + (i >> 4) ) & 0x0F0F0F0F0F0F0F0F );
    return ( i * (0x0101010101010101) ) >> 56;
}
#endif

#endif
