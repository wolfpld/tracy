#ifndef __TRACYPOPCNT_HPP__
#define __TRACYPOPCNT_HPP__

#include <limits.h>

#if defined _WIN64
#  include <intrin.h>
#  define TracyCountBits __popcnt64
#elif defined __GNUC__ || defined __clang__
static inline uint64_t TracyCountBits( uint64_t i )
{
    return uint64_t( __builtin_popcountll( i ) );
}
#else
static inline uint64_t TracyCountBits( uint64_t i )
{
    i = i - ( (i >> 1) & 0x5555555555555555 );
    i = ( i & 0x3333333333333333 ) + ( (i >> 2) & 0x3333333333333333 );
    i = ( (i + (i >> 4) ) & 0x0F0F0F0F0F0F0F0F );
    return ( i * (0x0101010101010101) ) >> 56;
}
#endif

#endif
