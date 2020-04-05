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
{
}

TextureCompression::~TextureCompression()
{
    delete[] m_buf;
    ZSTD_freeCCtx( m_cctx );
    ZSTD_freeDCtx( m_dctx );
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
    ZSTD_decompressDCtx( m_dctx, m_buf, outsz, image.ptr, image.csz );
    return m_buf;
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
        uint8_t tmp[4];
        memcpy( tmp, data+4, 4 );
        for( int k=0; k<4; k++ ) tmp[k] = DxtcIndexTable[(uint8_t)tmp[k]];
        memcpy( data+4, tmp, 4 );
        data += 8;
    }
    while( --blocks );
}

}
