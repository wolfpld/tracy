#include "../zstd/zstd.h"

#include "TracyEvent.hpp"
#include "TracyTextureCompression.hpp"

namespace tracy
{

TextureCompression::TextureCompression()
    : m_buf( nullptr )
    , m_bufSize( 0 )
    , m_cctx( ZSTD_createCCtx() )
    , m_dctx( ZSTD_createDCtx() )
    , m_dict( nullptr )
{
}

TextureCompression::~TextureCompression()
{
    delete[] m_buf;
    ZSTD_freeCCtx( m_cctx );
    ZSTD_freeDCtx( m_dctx );
    ZSTD_freeDDict( m_dict );
}

uint32_t TextureCompression::Pack( struct ZSTD_CCtx_s* ctx, char*& buf, size_t& bufsz, const char* image, uint32_t inBytes )
{
    const auto maxout = ZSTD_COMPRESSBOUND( inBytes );
    if( bufsz < maxout )
    {
        bufsz = maxout;
        delete[] buf;
        buf = new char[maxout];
    }
    assert( ctx );
    auto ret = (uint32_t)ZSTD_compressCCtx( ctx, buf, maxout, image, inBytes, 3 );
#ifndef TRACY_NO_STATISTICS
    m_inputBytes.fetch_add( inBytes, std::memory_order_relaxed );
    m_outputBytes.fetch_add( ret, std::memory_order_relaxed );
#endif
    return ret;
}

uint32_t TextureCompression::Pack( struct ZSTD_CCtx_s* ctx, const struct ZSTD_CDict_s* dict, char*& buf, size_t& bufsz, const char* image, uint32_t inBytes )
{
    const auto maxout = ZSTD_COMPRESSBOUND( inBytes );
    if( bufsz < maxout )
    {
        bufsz = maxout;
        delete[] buf;
        buf = new char[maxout];
    }
    assert( ctx );
    auto ret = (uint32_t)ZSTD_compress_usingCDict( ctx, buf, maxout, image, inBytes, dict );
#ifndef TRACY_NO_STATISTICS
    m_inputBytes.fetch_add( inBytes, std::memory_order_relaxed );
    m_outputBytes.fetch_add( ret, std::memory_order_relaxed );
#endif
    return ret;
}

const char* TextureCompression::Unpack( const FrameImage& image )
{
    const auto outsz = size_t( image.w ) * size_t( image.h ) / 2;
    if( m_bufSize < outsz )
    {
        m_bufSize = outsz;
        delete[] m_buf;
        m_buf = new char[outsz];
    }
    assert( m_dctx );
    if( m_dict )
    {
        ZSTD_decompress_usingDDict( m_dctx, m_buf, outsz, image.ptr, image.csz, m_dict );
    }
    else
    {
        ZSTD_decompressDCtx( m_dctx, m_buf, outsz, image.ptr, image.csz );
    }
    return m_buf;
}

static constexpr uint8_t Dxtc4To3Table[256] = {
     85,  84,  86,  86,  81,  80,  82,  82,  89,  88,  90,  90,  89,  88,  90,  90,
     69,  68,  70,  70,  65,  64,  66,  66,  73,  72,  74,  74,  73,  72,  74,  74,
    101, 100, 102, 102,  97,  96,  98,  98, 105, 104, 106, 106, 105, 104, 106, 106,
    101, 100, 102, 102,  97,  96,  98,  98, 105, 104, 106, 106, 105, 104, 106, 106,
     21,  20,  22,  22,  17,  16,  18,  18,  25,  24,  26,  26,  25,  24,  26,  26,
      5,   4,   6,   6,   1,   0,   2,   2,   9,   8,  10,  10,   9,   8,  10,  10,
     37,  36,  38,  38,  33,  32,  34,  34,  41,  40,  42,  42,  41,  40,  42,  42,
     37,  36,  38,  38,  33,  32,  34,  34,  41,  40,  42,  42,  41,  40,  42,  42,
    149, 148, 150, 150, 145, 144, 146, 146, 153, 152, 154, 154, 153, 152, 154, 154,
    133, 132, 134, 134, 129, 128, 130, 130, 137, 136, 138, 138, 137, 136, 138, 138,
    165, 164, 166, 166, 161, 160, 162, 162, 169, 168, 170, 170, 169, 168, 170, 170,
    165, 164, 166, 166, 161, 160, 162, 162, 169, 168, 170, 170, 169, 168, 170, 170,
    149, 148, 150, 150, 145, 144, 146, 146, 153, 152, 154, 154, 153, 152, 154, 154,
    133, 132, 134, 134, 129, 128, 130, 130, 137, 136, 138, 138, 137, 136, 138, 138,
    165, 164, 166, 166, 161, 160, 162, 162, 169, 168, 170, 170, 169, 168, 170, 170,
    165, 164, 166, 166, 161, 160, 162, 162, 169, 168, 170, 170, 169, 168, 170, 170
};

static tracy_force_inline int max3( int a, int b, int c )
{
    if( a > b )
    {
        return a > c ? a : c;
    }
    else
    {
        return b > c ? b : c;
    }
}

static constexpr int TrTbl1[] = { 12, 12, 12, 12, 6, 6, 6, 6, 6, 6, 6, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 };
static constexpr int TrTbl2[] = { 12, 12, 6, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 };
static constexpr int TrTbl3[] = { 48, 48, 48, 32, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24 };

void TextureCompression::Rdo( char* data, size_t blocks )
{
    assert( blocks > 0 );
    do
    {
        uint64_t blk;
        memcpy( &blk, data, 8 );

        uint32_t idx = blk >> 32;
        if( idx == 0x55555555 )
        {
            data += 8;
            continue;
        }

        uint16_t c0 = blk & 0xFFFF;
        uint16_t c1 = ( blk >> 16 ) & 0xFFFF;

        const int r0b = c0 & 0xF800;
        const int g0b = c0 & 0x07E0;
        const int b0b = c0 & 0x001F;

        const int r1b = c1 & 0xF800;
        const int g1b = c1 & 0x07E0;
        const int b1b = c1 & 0x001F;

        const int r0 = ( r0b >> 8 ) | ( r0b >> 13 );
        const int g0 = ( g0b >> 3 ) | ( g0b >> 9 );
        const int b0 = ( b0b << 3 ) | ( b0b >> 2 );

        const int r1 = ( r1b >> 8 ) | ( r1b >> 13 );
        const int g1 = ( g1b >> 3 ) | ( g1b >> 9 );
        const int b1 = ( b1b << 3 ) | ( b1b >> 2 );

        const int dr = abs( r0 - r1 );
        const int dg = abs( g0 - g1 );
        const int db = abs( b0 - b1 );

        const int maxChan1 = max3( r0-1, g0, b0-2 );
        const int maxDelta1 = max3( dr-1, dg, db-2 );
        const int tr1 = TrTbl1[maxChan1 / 4];
        if( maxDelta1 <= tr1 )
        {
            uint64_t blk =
                ( ( ( r0b + r1b ) >> 1 ) & 0xF800 ) |
                ( ( ( g0b + g1b ) >> 1 ) & 0x07E0 ) |
                ( ( ( b0b + b1b ) >> 1 ) );
            memcpy( data, &blk, 8 );
        }
        else
        {
            const int maxChan23 = max3( r0-2, g0, b0-5 );
            const int maxDelta23 = max3( dr-2, dg, db-5 );
            const int tr2 = TrTbl2[maxChan23 / 16];
            if( maxDelta23 <= tr2 )
            {
                idx &= 0x55555555;
                memcpy( data+4, &idx, 4 );
            }
            else
            {
                const int tr3 = TrTbl3[maxChan23 / 16];
                if( maxDelta23 <= tr3 )
                {
                    uint64_t c = c1 | ( uint64_t( c0 ) << 16 );
                    for( int k=0; k<4; k++ ) c |= uint64_t( Dxtc4To3Table[(idx >> (k*8)) & 0xFF] ) << ( 32 + k*8 );
                    memcpy( data, &c, 8 );
                }
            }
        }

        data += 8;
    }
    while( --blocks );
}

static constexpr uint8_t DxtcIndexTable[256] = {
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

void TextureCompression::FixOrder( char* data, size_t blocks )
{
    assert( blocks > 0 );
    do
    {
        uint32_t res = 0;
        uint32_t tmp;
        memcpy( &tmp, data+4, 4 );
        for( int k=0; k<4; k++ ) res |= DxtcIndexTable[(tmp >> (k*8)) & 0xFF] << (k*8);
        memcpy( data+4, &res, 4 );
        data += 8;
    }
    while( --blocks );
}

}
