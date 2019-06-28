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
static const uint8_t IndexTableSIMD[256] = {
    85,     87,     86,     84,     93,     95,     94,     92,     89,     91,     90,     88,     81,     83,     82,     80,
    117,    119,    118,    116,    125,    127,    126,    124,    121,    123,    122,    120,    113,    115,    114,    112,
    101,    103,    102,    100,    109,    111,    110,    108,    105,    107,    106,    104,    97,     99,     98,     96,
    69,     71,     70,     68,     77,     79,     78,     76,     73,     75,     74,     72,     65,     67,     66,     64,
    213,    215,    214,    212,    221,    223,    222,    220,    217,    219,    218,    216,    209,    211,    210,    208,
    245,    247,    246,    244,    253,    255,    254,    252,    249,    251,    250,    248,    241,    243,    242,    240,
    229,    231,    230,    228,    237,    239,    238,    236,    233,    235,    234,    232,    225,    227,    226,    224,
    197,    199,    198,    196,    205,    207,    206,    204,    201,    203,    202,    200,    193,    195,    194,    192,
    149,    151,    150,    148,    157,    159,    158,    156,    153,    155,    154,    152,    145,    147,    146,    144,
    181,    183,    182,    180,    189,    191,    190,    188,    185,    187,    186,    184,    177,    179,    178,    176,
    165,    167,    166,    164,    173,    175,    174,    172,    169,    171,    170,    168,    161,    163,    162,    160,
    133,    135,    134,    132,    141,    143,    142,    140,    137,    139,    138,    136,    129,    131,    130,    128,
    21,     23,     22,     20,     29,     31,     30,     28,     25,     27,     26,     24,     17,     19,     18,     16,
    53,     55,     54,     52,     61,     63,     62,     60,     57,     59,     58,     56,     49,     51,     50,     48,
    37,     39,     38,     36,     45,     47,     46,     44,     41,     43,     42,     40,     33,     35,     34,     32,
    5,      7,      6,      4,      13,     15,     14,     12,     9,      11,     10,     8,      1,      3,      2,      0
};

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

    __m128i mask0 = _mm_set1_epi32( 0x00000003 );
    __m128i mask1 = _mm_set1_epi32( 0x00000300 );
    __m128i mask2 = _mm_set1_epi32( 0x00030000 );
    __m128i mask3 = _mm_set1_epi32( 0x03000000 );

    __m128i p1 = _mm_and_si128( p0, mask0 );
    __m128i p2 = _mm_srai_epi32( _mm_and_si128( p0, mask1 ), 6 );
    __m128i p3 = _mm_srai_epi32( _mm_and_si128( p0, mask2 ), 12 );
    __m128i p4 = _mm_srai_epi32( _mm_and_si128( p0, mask3 ), 18 );

    __m128i p5 = _mm_or_si128( p1, p2 );
    __m128i p6 = _mm_or_si128( p3, p4 );
    __m128i p7 = _mm_or_si128( p5, p6 );

    __m128i p8 = _mm_packus_epi32( p7, p7 );
    __m128i p = _mm_packus_epi16( p8, p8 );

    uint32_t vmin = _mm_cvtsi128_si32( min );
    uint32_t vmax = _mm_cvtsi128_si32( max );
    uint32_t vp = _mm_cvtsi128_si32( p );

    uint32_t data = 0;
    for( int i=0; i<4; i++ )
    {
        uint8_t idx = IndexTableSIMD[vp & 0xFF];
        vp >>= 8;
        data |= idx << (i*8);
    }

    return uint64_t( ( uint64_t( to565( vmin ) ) << 16 ) | to565( vmax ) | ( uint64_t( data ) << 32 ) );
#elif defined __ARM_NEON
    uint32x4_t mask = vdupq_n_u32( 0xFFFFFF );
    uint8x16_t l0 = vreinterpretq_u8_u32( vandq_u32( mask, vld1q_u32( (uint32_t*)src ) ) );
    uint8x16_t l1 = vreinterpretq_u8_u32( vandq_u32( mask, vld1q_u32( (uint32_t*)src + 4 ) ) );
    uint8x16_t l2 = vreinterpretq_u8_u32( vandq_u32( mask, vld1q_u32( (uint32_t*)src + 8 ) ) );
    uint8x16_t l3 = vreinterpretq_u8_u32( vandq_u32( mask, vld1q_u32( (uint32_t*)src + 12 ) ) );

    uint8x16_t min0 = vminq_u8( l0, l1 );
    uint8x16_t min1 = vminq_u8( l2, l3 );
    uint8x16_t min2 = vminq_u8( min0, min1 );

    uint8x16_t max0 = vmaxq_u8( l0, l1 );
    uint8x16_t max1 = vmaxq_u8( l2, l3 );
    uint8x16_t max2 = vmaxq_u8( max0, max1 );

    uint8x16_t min3 = vreinterpretq_u8_u32( vrev64q_u32( vreinterpretq_u32_u8( min2 ) ) );
    uint8x16_t max3 = vreinterpretq_u8_u32( vrev64q_u32( vreinterpretq_u32_u8( max2 ) ) );

    uint8x16_t min4 = vminq_u8( min2, min3 );
    uint8x16_t max4 = vmaxq_u8( max2, max3 );

    uint8x16_t min5 = vcombine_u8( vget_high_u8( min4 ), vget_low_u8( min4 ) );
    uint8x16_t max5 = vcombine_u8( vget_high_u8( max4 ), vget_low_u8( max4 ) );

    uint8x16_t rmin = vminq_u8( min4, min5 );
    uint8x16_t rmax = vmaxq_u8( max4, max5 );

    uint8x16_t range1 = vsubq_u8( rmax, rmin );
    uint8x8_t range2 = vget_low_u8( range1 );
    uint8x8x2_t range3 = vzip_u8( range2, vdup_n_u8( 0 ) );
    uint16x4_t range4 = vreinterpret_u16_u8( range3.val[0] );

    uint16_t vrange1;
#ifndef __aarch64__
    uint16x4_t range5 = vpadd_u16( range4, range4 );
    uint16x4_t range6 = vpadd_u16( range5, range5 );
    vst1_lane_u16( &vrange1, range6, 0 );
#else
    vrange1 = vaddv_s16( vreinterpret_s16_u16( range4 ) );
#endif

    uint32_t vrange2 = ( 2 << 16 ) / uint32_t( vrange1 + 1 );
    uint16x8_t range = vdupq_n_u16( vrange2 );

    uint8x16_t inset = vshrq_n_u8( range1, 4 );
    uint8x16_t min = vaddq_u8( rmin, inset );
    uint8x16_t max = vsubq_u8( rmax, inset );

    uint8x16_t c0 = vsubq_u8( l0, rmin );
    uint8x16_t c1 = vsubq_u8( l1, rmin );
    uint8x16_t c2 = vsubq_u8( l2, rmin );
    uint8x16_t c3 = vsubq_u8( l3, rmin );

    uint16x8_t is0 = vpaddlq_u8( c0 );
    uint16x8_t is1 = vpaddlq_u8( c1 );
    uint16x8_t is2 = vpaddlq_u8( c2 );
    uint16x8_t is3 = vpaddlq_u8( c3 );

#ifndef __aarch64__
    uint16x4_t is4 = vpadd_u16( vget_low_u16( is0 ), vget_high_u16( is0 ) );
    uint16x4_t is5 = vpadd_u16( vget_low_u16( is1 ), vget_high_u16( is1 ) );
    uint16x4_t is6 = vpadd_u16( vget_low_u16( is2 ), vget_high_u16( is2 ) );
    uint16x4_t is7 = vpadd_u16( vget_low_u16( is3 ), vget_high_u16( is3 ) );

    uint16x8_t s0 = vcombine_u16( is4, is5 );
    uint16x8_t s1 = vcombine_u16( is6, is7 );
#else
    uint16x8_t s0 = vpaddq_u16( is0, is1 );
    uint16x8_t s1 = vpaddq_u16( is2, is3 );
#endif

    uint16x8_t m0 = vreinterpretq_u16_s16( vqdmulhq_s16( vreinterpretq_s16_u16( s0 ), vreinterpretq_s16_u16( range ) ) );
    uint16x8_t m1 = vreinterpretq_u16_s16( vqdmulhq_s16( vreinterpretq_s16_u16( s1 ), vreinterpretq_s16_u16( range ) ) );

    uint8x8_t p00 = vmovn_u16( m0 );
    uint8x8_t p01 = vmovn_u16( m1 );
    uint8x16_t p0 = vcombine_u8( p00, p01 );

    uint32x4_t mask0 = vdupq_n_u32( 0x00000003 );
    uint32x4_t mask1 = vdupq_n_u32( 0x00000300 );
    uint32x4_t mask2 = vdupq_n_u32( 0x00030000 );
    uint32x4_t mask3 = vdupq_n_u32( 0x03000000 );

    uint32x4_t p1 = vandq_u32( vreinterpretq_u32_u8( p0 ), mask0 );
    uint32x4_t p2 = vshrq_n_u32( vandq_u32( vreinterpretq_u32_u8( p0 ), mask1 ), 6 );
    uint32x4_t p3 = vshrq_n_u32( vandq_u32( vreinterpretq_u32_u8( p0 ), mask2 ), 12 );
    uint32x4_t p4 = vshrq_n_u32( vandq_u32( vreinterpretq_u32_u8( p0 ), mask3 ), 18 );

    uint32x4_t p5 = vorrq_u32( p1, p2 );
    uint32x4_t p6 = vorrq_u32( p3, p4 );
    uint32x4_t p7 = vorrq_u32( p5, p6 );

    uint16x4x2_t p8 = vuzp_u16( vget_low_u16( vreinterpretq_u16_u32( p7 ) ), vget_high_u16( vreinterpretq_u16_u32( p7 ) ) );
    uint8x8x2_t p9 = vuzp_u8( vreinterpret_u8_u16( p8.val[0] ), vreinterpret_u8_u16( p8.val[0] ) );

    uint32_t vmin, vmax, vp;
    vst1q_lane_u32( &vmin, vreinterpretq_u32_u8( min ), 0 );
    vst1q_lane_u32( &vmax, vreinterpretq_u32_u8( max ), 0 );
    vst1_lane_u32( &vp, vreinterpret_u32_u8( p9.val[0] ), 0 );

    uint32_t data = 0;
    for( int i=0; i<4; i++ )
    {
        uint8_t idx = IndexTableSIMD[vp & 0xFF];
        vp >>= 8;
        data |= idx << (i*8);
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

    const uint32_t range = ( 4 << 16 ) / ( 1 + max[0] - min[0] + max[1] - min[1] + max[2] - min[2] );
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
        const uint8_t idx = IndexTable[( c * range ) >> 16];
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
