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

static inline uint16_t to565( uint32_t c )
{
    return
        ( ( c & 0xF80000 ) >> 19 ) |
        ( ( c & 0x00FC00 ) >> 5 ) |
        ( ( c & 0x0000F8 ) << 8 );
}

static uint64_t CheckSolid( const uint8_t* src )
{
#ifdef __SSE4_1__
    __m128i mask = _mm_set1_epi32( 0xF8FCF8 );
    __m128i d0 = _mm_and_si128( _mm_loadu_si128(((__m128i*)src) + 0), mask );
    __m128i d1 = _mm_and_si128( _mm_loadu_si128(((__m128i*)src) + 1), mask );
    __m128i d2 = _mm_and_si128( _mm_loadu_si128(((__m128i*)src) + 2), mask );
    __m128i d3 = _mm_and_si128( _mm_loadu_si128(((__m128i*)src) + 3), mask );

    __m128i c = _mm_shuffle_epi32(d0, _MM_SHUFFLE(0, 0, 0, 0));

    __m128i c0 = _mm_cmpeq_epi8(d0, c);
    __m128i c1 = _mm_cmpeq_epi8(d1, c);
    __m128i c2 = _mm_cmpeq_epi8(d2, c);
    __m128i c3 = _mm_cmpeq_epi8(d3, c);

    __m128i m0 = _mm_and_si128(c0, c1);
    __m128i m1 = _mm_and_si128(c2, c3);
    __m128i m = _mm_and_si128(m0, m1);

    if (!_mm_testc_si128(m, _mm_set1_epi32(-1)))
    {
        return 0;
    }
    else
    {
        return to565( src[0], src[1], src[2] );
    }
#elif defined __ARM_NEON
    uint32x4_t mask = vdupq_n_u32( 0xF8FCF8 );
    uint32x4_t d0 = vandq_u32( mask, vld1q_u32( (uint32_t*)src ) );
    uint32x4_t d1 = vandq_u32( mask, vld1q_u32( (uint32_t*)src + 4 ) );
    uint32x4_t d2 = vandq_u32( mask, vld1q_u32( (uint32_t*)src + 8 ) );
    uint32x4_t d3 = vandq_u32( mask, vld1q_u32( (uint32_t*)src + 12 ) );

    uint32x4_t c = vdupq_n_u32( d0[0] );

    uint32x4_t c0 = vceqq_u32( d0, c );
    uint32x4_t c1 = vceqq_u32( d1, c );
    uint32x4_t c2 = vceqq_u32( d2, c );
    uint32x4_t c3 = vceqq_u32( d3, c );

    uint32x4_t m0 = vandq_u32( c0, c1 );
    uint32x4_t m1 = vandq_u32( c2, c3 );
    int64x2_t m = vreinterpretq_s64_u32( vandq_u32( m0, m1 ) );

    if( m[0] != -1 || m[1] != -1 )
    {
        return 0;
    }
    else
    {
        return to565( src[0], src[1], src[2] );
    }
#else
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
#endif
}

static const uint8_t IndexTable[4] = { 1, 3, 2, 0 };

static uint64_t ProcessRGB( const uint8_t* src )
{
    const auto solid = CheckSolid( src );
    if( solid != 0 ) return solid;

#ifdef __SSE4_1__
    __m128i mask = _mm_set1_epi32( 0xFFFFFF );
    __m128i l0 = _mm_and_si128( _mm_loadu_si128(((__m128i*)src) + 0), mask );
    __m128i l1 = _mm_and_si128( _mm_loadu_si128(((__m128i*)src) + 1), mask );
    __m128i l2 = _mm_and_si128( _mm_loadu_si128(((__m128i*)src) + 2), mask );
    __m128i l3 = _mm_and_si128( _mm_loadu_si128(((__m128i*)src) + 3), mask );

    __m128i min0 = _mm_min_epu8( l0, l1 );
    __m128i min1 = _mm_min_epu8( l2, l3 );
    __m128i min2 = _mm_min_epu8( min0, min1 );

    __m128i max0 = _mm_max_epu8( l0, l1 );
    __m128i max1 = _mm_max_epu8( l2, l3 );
    __m128i max2 = _mm_max_epu8( max0, max1 );

    __m128i min3 = _mm_shuffle_epi32( min2, _MM_SHUFFLE( 2, 3, 0, 1 ) );
    __m128i max3 = _mm_shuffle_epi32( max2, _MM_SHUFFLE( 2, 3, 0, 1 ) );
    __m128i min4 = _mm_min_epu8( min2, min3 );
    __m128i max4 = _mm_max_epu8( max2, max3 );

    __m128i min5 = _mm_shuffle_epi32( min4, _MM_SHUFFLE( 0, 0, 2, 2 ) );
    __m128i max5 = _mm_shuffle_epi32( max4, _MM_SHUFFLE( 0, 0, 2, 2 ) );
    __m128i rmin = _mm_min_epu8( min4, min5 );
    __m128i rmax = _mm_max_epu8( max4, max5 );

    __m128i range1 = _mm_subs_epu8( rmax, rmin );
    __m128i range2 = _mm_maddubs_epi16( range1, _mm_set1_epi8( 1 ) );
    __m128i range3 = _mm_hadd_epi16( range2, range2 );
    __m128i range4 = _mm_add_epi16( range3, _mm_set1_epi16( 1 ) );

    uint32_t vrange1 = _mm_cvtsi128_si32( range4 ) & 0xFFFF;
    uint32_t vrange2 = ( 4 << 16 ) / vrange1;

    __m128i range = _mm_set1_epi16( vrange2 );

    __m128i inset1 = _mm_srli_epi16( range1, 4 );
    __m128i inset = _mm_and_si128( inset1, _mm_set1_epi8( 0xF ) );
    __m128i min = _mm_adds_epu8( rmin, inset );
    __m128i max = _mm_subs_epu8( rmax, inset );

    __m128i c0 = _mm_subs_epu8( l0, rmin );
    __m128i c1 = _mm_subs_epu8( l1, rmin );
    __m128i c2 = _mm_subs_epu8( l2, rmin );
    __m128i c3 = _mm_subs_epu8( l3, rmin );

    __m128i is0 = _mm_maddubs_epi16( c0, _mm_set1_epi8( 1 ) );
    __m128i is1 = _mm_maddubs_epi16( c1, _mm_set1_epi8( 1 ) );
    __m128i is2 = _mm_maddubs_epi16( c2, _mm_set1_epi8( 1 ) );
    __m128i is3 = _mm_maddubs_epi16( c3, _mm_set1_epi8( 1 ) );

    __m128i s0 = _mm_hadd_epi16( is0, is1 );
    __m128i s1 = _mm_hadd_epi16( is2, is3 );

    __m128i m0 = _mm_mulhi_epu16( s0, range );
    __m128i m1 = _mm_mulhi_epu16( s1, range );

    __m128i p0 = _mm_packus_epi16( m0, m1 );

    uint32_t vmin = _mm_cvtsi128_si32( min );
    uint32_t vmax = _mm_cvtsi128_si32( max );

    uint32_t vp[4];
    _mm_store_si128( (__m128i*)vp, p0 );

    uint32_t data = 0;
    int k = 0;
    for( int i=0; i<4; i++ )
    {
        uint32_t p = vp[i];
        for( int j=0; j<4; j++ )
        {
            uint8_t idx = IndexTable[p & 0x3];
            p >>= 8;
            data |= idx << (k*2);
            k++;
        }
    }

    return uint64_t( ( uint64_t( to565( vmin ) ) << 16 ) | to565( vmax ) | ( uint64_t( data ) << 32 ) );
#else
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

    const uint32_t range = ( 4 << 13 ) / ( 1 + max[0] - min[0] + max[1] - min[1] + max[2] - min[2] );
    const uint32_t rmin = min[0] + min[1] + min[2];
    for( int i=0; i<3; i++ )
    {
        const uint8_t inset = ( max[i] - min[i] ) >> 4;
        min[i] += inset;
        max[i] -= inset;
    }

    uint32_t data = 0;
    for( int i=0; i<16; i++ )
    {
        const uint32_t c = src[0] + src[1] + src[2] - rmin;
        const uint8_t idx = IndexTable[( c * range ) >> 13];
        data |= idx << (i*2);
        src += 4;
    }

    return uint64_t( ( uint64_t( to565( min[0], min[1], min[2] ) ) << 16 ) | to565( max[0], max[1], max[2] ) | ( uint64_t( data ) << 32 ) );
#endif
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
