#include <algorithm>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>

inline float sqrtfast( float v )
{
    union
    {
        int i;
        float f;
    } u;

    u.f = v;
    u.i -= 1 << 23;
    u.i >>= 1;
    u.i += 1 << 29;
    return u.f;
}

inline float linear2sRGB( float v )
{
    float s1 = sqrtfast( v );
    float s2 = sqrtfast( s1 );
    float s3 = sqrtfast( s2 );
    return 0.585122381f * s1 + 0.783140355f * s2 - 0.368262736f * s3;
}

int lerp( int v0, int v1, float t )
{
    return int( ( 1-t ) * v0 + t * v1 );
}

inline float sRGB2linear( float v )
{
    return v * ( v * ( v * 0.305306011f + 0.682171111f ) + 0.012522878f );
}

int main()
{
    int c0 = std::min( 255, int( sRGB2linear( 1.f ) * 255 ) );
    int c1 = std::min( 255, int( sRGB2linear( 0x44 / 255.f ) * 255 ) );

    int s0 = std::min( 255, int( sRGB2linear( 1.f ) * 255 * 0.5 ) );
    int s1 = std::min( 255, int( sRGB2linear( 0x44 / 255.f ) * 255 * 0.5 ) );

    float target = 80.f;

    uint32_t t[256];
    memset( t, 0, sizeof( uint32_t ) * 256 );

    for( int i=1; i<128; i++ )
    {
        float m = (i-1) / target;
        int l0 = std::min( 255, lerp( s0, c0, m ) );
        int l1 = std::min( 255, lerp( s1, c1, m ) );
        int g0 = std::min( 255, int( linear2sRGB( l0/255.f ) * 255 ) );
        int g1 = std::min( 255, int( linear2sRGB( l1/255.f ) * 255 ) );
        g0 = l0;
        g1 = l1;
        t[i] = 0xFF000000 | ( g1 << 16 ) | ( g0 << 8 ) | g1;
        t[uint8_t(-i)] = 0xFF000000 | ( g1 << 16 ) | ( g1 << 8 ) | g0;
    }

    printf( "uint32_t MemDecayColor[256] = {\n" );
    for( int i=0; i<256; i += 8 )
    {
        printf( "   " );
        for( int j=i; j<i+8; j++ )
        {
            printf( " 0x%X,", t[j] );
        }
        printf( "\n" );
    }
    printf( "};\n" );
}
