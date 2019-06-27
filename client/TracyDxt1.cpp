#include "TracyDxt1.hpp"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#ifdef __ARM_NEON
#  include <arm_neon.h>
#endif

#if defined __AVX__ && !defined __SSE4_1__
#  define __SSE4_1__
#endif

#ifdef _MSC_VER
#  ifdef __SSE4_1__
#    include <intrin.h>
#  else
#    include <x86intrin.h>
#  endif
#endif

namespace tracy
{

static inline uint16_t to565( uint8_t r, uint8_t g, uint8_t b )
{
    return ( ( r & 0xF8 ) << 8 ) | ( ( g & 0xFC ) << 3 ) | ( b >> 3 );
}

static uint64_t CheckSolid( const uint8_t* src )
{
    const auto ref = to565( src[0], src[1], src[2] );
    src += 4;
    for( int i=1; i<16; i++ )
    {
        if( to565( src[0], src[1], src[2] ) != ref )
        {
            return 0;
        }
        src += 4;
    }
    return uint64_t( ref );
}

static const uint8_t IndexTable[4] = { 1, 3, 2, 0 };

static uint64_t ProcessRGB( const uint8_t* src )
{
    const auto solid = CheckSolid( src );
    if( solid != 0 ) return solid;

    uint8_t min[3] = { src[0], src[1], src[2] };
    uint8_t max[3] = { src[0], src[1], src[2] };
    auto tmp = src + 4;
    for( int i=1; i<16; i++ )
    {
        for( int j=0; j<3; j++ )
        {
            if( tmp[j] < min[j] ) min[j] = tmp[j];
            else if( tmp[j] > max[j] ) max[j] = tmp[j];
        }
        tmp += 4;
    }

    uint32_t range = ( 4 << 13 ) / ( 1 + max[0] - min[0] + max[1] - min[1] + max[2] - min[2] );
    uint8_t rmin[3] = { min[0], min[1], min[2] };
    for( int i=0; i<3; i++ )
    {
        const uint8_t inset = ( max[i] - min[i] ) >> 4;
        min[i] += inset;
        max[i] -= inset;
    }

    uint32_t data = 0;
    for( int i=0; i<16; i++ )
    {
        uint32_t c = src[0] - rmin[0] + src[1] - rmin[1] + src[2] - rmin[2];
        uint8_t idx = IndexTable[( c * range ) >> 13];
        data |= idx << (i*2);
        src += 4;
    }

    return uint64_t( ( uint64_t( to565( min[0], min[1], min[2] ) ) << 16 ) | to565( max[0], max[1], max[2] ) | ( uint64_t( data ) << 32 ) );
}

void CompressImageDxt1( const char* src, char* dst, int w, int h )
{
    assert( (w % 4) == 0 && (h % 4) == 0 );

    uint32_t buf[4*4];
    int i = 0;

    auto ptr = dst;
    auto blocks = w * h / 16;
    do
    {
        auto tmp = (char*)buf;
        memcpy( tmp,        src,          4*4 );
        memcpy( tmp + 4*4,  src + w * 4,  4*4 );
        memcpy( tmp + 8*4,  src + w * 8,  4*4 );
        memcpy( tmp + 12*4, src + w * 12, 4*4 );
        src += 4*4;
        if( ++i == w/4 )
        {
            src += w * 3 * 4;
            i = 0;
        }

        const auto c = ProcessRGB( (uint8_t*)buf );
        memcpy( ptr, &c, sizeof( uint64_t ) );
        ptr += sizeof( uint64_t );
    }
    while( --blocks );
}

}
