#include <algorithm>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>

inline float linear2sRGB( float v )
{
    float s1 = sqrt( v );
    float s2 = sqrt( s1 );
    float s3 = sqrt( s2 );
    return 0.585122381f * s1 + 0.783140355f * s2 - 0.368262736f * s3;
}

float lerp( float v0, float v1, float t )
{
    return ( 1-t ) * v0 + t * v1;
}

inline float sRGB2linear( float v )
{
    return v * ( v * ( v * 0.305306011f + 0.682171111f ) + 0.012522878f );
}

int main()
{
    int c0 = 0x3333FF;
    int c1 = 0x33FF33;

    uint32_t t[256] = {};

    float r0 = ( c0 & 0xFF ) / 255.f;
    float r1 = ( c1 & 0xFF ) / 255.f;
    float g0 = ( ( c0 >> 8 ) & 0xFF ) / 255.f;
    float g1 = ( ( c1 >> 8 ) & 0xFF ) / 255.f;
    float b0 = ( ( c0 >> 16 ) & 0xFF ) / 255.f;
    float b1 = ( ( c1 >> 16 ) & 0xFF ) / 255.f;

    for( int i=0; i<256; i++ )
    {
        float m = i / 255.f;
        float rf = linear2sRGB( lerp( sRGB2linear( r0 ), sRGB2linear( r1 ), m ) );
        float gf = linear2sRGB( lerp( sRGB2linear( g0 ), sRGB2linear( g1 ), m ) );
        float bf = linear2sRGB( lerp( sRGB2linear( b0 ), sRGB2linear( b1 ), m ) );

        int r = (int)std::clamp( rf * 255.f, 0.f, 255.f );
        int g = (int)std::clamp( gf * 255.f, 0.f, 255.f );
        int b = (int)std::clamp( bf * 255.f, 0.f, 255.f );

        t[i] = 0xFF000000 | ( b << 16 ) | ( g << 8 ) | r;
    }

    printf( "uint32_t GoodnessColor[256] = {\n" );
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
