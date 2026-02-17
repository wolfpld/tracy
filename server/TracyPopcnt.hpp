#ifndef __TRACYPOPCNT_HPP__
#define __TRACYPOPCNT_HPP__

#include <limits.h>
#include <stdint.h>

#if defined __GNUC__ || defined __clang__
static inline uint64_t TracyCountBits( uint64_t i )
{
    return uint64_t( __builtin_popcountll( i ) );
}
static inline uint64_t TracyLzcnt( uint64_t i )
{
    return uint64_t( __builtin_clzll( i ) );
}
#elif defined(_M_ARM64)
#include <arm_neon.h>
static inline uint64_t TracyCountBits( uint64_t i )
{
    uint8x8_t v = vreinterpret_u8_u64( vdup_n_u64( i ) );
    uint8x8_t popcnt = vcnt_u8( v );
    return (uint64_t)vaddlv_u8( popcnt );
}
static inline uint64_t TracyLzcnt( uint64_t i )
{
    unsigned long index;
    uint64_t leadingZeros = 64;
    if( _BitScanReverse64( &index, i ) )
    {
        leadingZeros = 63 - index;
    }
    return leadingZeros;
}
#elif defined _WIN64
#  include <intrin.h>
#  define TracyCountBits __popcnt64
#  define TracyLzcnt __lzcnt64
#else
static inline uint64_t TracyCountBits( uint64_t i )
{
    i = i - ( (i >> 1) & 0x5555555555555555 );
    i = ( i & 0x3333333333333333 ) + ( (i >> 2) & 0x3333333333333333 );
    i = ( (i + (i >> 4) ) & 0x0F0F0F0F0F0F0F0F );
    return ( i * (0x0101010101010101) ) >> 56;
}
static inline uint64_t TracyLzcnt( uint64_t i )
{
    i |= i >> 1;
    i |= i >> 2;
    i |= i >> 4;
    i |= i >> 8;
    i |= i >> 16;
    i |= i >> 32;
    return 64 - TracyCountBits( i );
}
#endif

#endif
