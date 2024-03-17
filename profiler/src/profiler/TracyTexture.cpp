#include <inttypes.h>
#include <string.h>

#ifdef __EMSCRIPTEN__
#  include <emscripten/html5.h>
#  include <GLES2/gl2.h>
#else
#  include "../profiler/src/imgui/imgui_impl_opengl3_loader.h"
#endif
#include "TracyTexture.hpp"
#include "../public/common/TracyForceInline.hpp"

#ifndef COMPRESSED_RGB_S3TC_DXT1_EXT
#  define COMPRESSED_RGB_S3TC_DXT1_EXT 0x83F0
#endif

namespace tracy
{

static bool s_hardwareS3tc;

void InitTexture()
{
#ifdef __EMSCRIPTEN__
    s_hardwareS3tc = emscripten_webgl_enable_extension( emscripten_webgl_get_current_context(), "WEBGL_compressed_texture_s3tc" );
#else
    s_hardwareS3tc = false;
    GLint num;
    glGetIntegerv( GL_NUM_EXTENSIONS, &num );
    for( GLint i=0; i<num; i++ )
    {
        auto ext = (const char*)glGetStringi( GL_EXTENSIONS, GLuint( i ) );
        if( strcmp( ext, "GL_EXT_texture_compression_s3tc" ) == 0 )
        {
            s_hardwareS3tc = true;
            break;
        }
    }
#endif
}

void* MakeTexture( bool zigzag )
{
    GLuint tex;
    glGenTextures( 1, &tex );
    glBindTexture( GL_TEXTURE_2D, tex );
    glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, zigzag ? GL_LINEAR_MIPMAP_LINEAR : GL_LINEAR );
    glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR );
    glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, zigzag ? GL_REPEAT : GL_CLAMP_TO_EDGE );
    glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
    return (void*)(intptr_t)tex;
}

void FreeTexture( void* _tex, void(*runOnMainThread)(const std::function<void()>&, bool) )
{
    auto tex = (GLuint)(intptr_t)_tex;
    runOnMainThread( [tex] { glDeleteTextures( 1, &tex ); }, false );
}

static tracy_force_inline void DecodeDxt1Part( uint64_t d, uint32_t* dst, uint32_t w )
{
    uint8_t* in = (uint8_t*)&d;
    uint16_t c0, c1;
    uint32_t idx;
    memcpy( &c0, in, 2 );
    memcpy( &c1, in+2, 2 );
    memcpy( &idx, in+4, 4 );

    uint8_t r0 = ( ( c0 & 0xF800 ) >> 8 ) | ( ( c0 & 0xF800 ) >> 13 );
    uint8_t g0 = ( ( c0 & 0x07E0 ) >> 3 ) | ( ( c0 & 0x07E0 ) >> 9 );
    uint8_t b0 = ( ( c0 & 0x001F ) << 3 ) | ( ( c0 & 0x001F ) >> 2 );

    uint8_t r1 = ( ( c1 & 0xF800 ) >> 8 ) | ( ( c1 & 0xF800 ) >> 13 );
    uint8_t g1 = ( ( c1 & 0x07E0 ) >> 3 ) | ( ( c1 & 0x07E0 ) >> 9 );
    uint8_t b1 = ( ( c1 & 0x001F ) << 3 ) | ( ( c1 & 0x001F ) >> 2 );

    uint32_t dict[4];

    dict[0] = 0xFF000000 | ( b0 << 16 ) | ( g0 << 8 ) | r0;
    dict[1] = 0xFF000000 | ( b1 << 16 ) | ( g1 << 8 ) | r1;

    uint32_t r, g, b;
    if( c0 > c1 )
    {
        r = (2*r0+r1)/3;
        g = (2*g0+g1)/3;
        b = (2*b0+b1)/3;
        dict[2] = 0xFF000000 | ( b << 16 ) | ( g << 8 ) | r;
        r = (2*r1+r0)/3;
        g = (2*g1+g0)/3;
        b = (2*b1+b0)/3;
        dict[3] = 0xFF000000 | ( b << 16 ) | ( g << 8 ) | r;
    }
    else
    {
        r = (int(r0)+r1)/2;
        g = (int(g0)+g1)/2;
        b = (int(b0)+b1)/2;
        dict[2] = 0xFF000000 | ( b << 16 ) | ( g << 8 ) | r;
        dict[3] = 0xFF000000;
    }

    memcpy( dst+0, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+1, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+2, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+3, dict + (idx & 0x3), 4 );
    idx >>= 2;
    dst += w;

    memcpy( dst+0, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+1, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+2, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+3, dict + (idx & 0x3), 4 );
    idx >>= 2;
    dst += w;

    memcpy( dst+0, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+1, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+2, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+3, dict + (idx & 0x3), 4 );
    idx >>= 2;
    dst += w;

    memcpy( dst+0, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+1, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+2, dict + (idx & 0x3), 4 );
    idx >>= 2;
    memcpy( dst+3, dict + (idx & 0x3), 4 );
}

void UpdateTexture( void* _tex, const char* data, int w, int h )
{
    auto tex = (GLuint)(intptr_t)_tex;
    glBindTexture( GL_TEXTURE_2D, tex );
    if( s_hardwareS3tc )
    {
        glCompressedTexImage2D( GL_TEXTURE_2D, 0, COMPRESSED_RGB_S3TC_DXT1_EXT, w, h, 0, w * h / 2, data );
    }
    else
    {
        auto tmp = new uint32_t[w*h];
        auto src = (const uint64_t*)data;
        auto dst = tmp;
        for( int y=0; y<h/4; y++ )
        {
            for( int x=0; x<w/4; x++ )
            {
                uint64_t d = *src++;
                DecodeDxt1Part( d, dst, w );
                dst += 4;
            }
            dst += w*3;
        }
        glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, tmp );
        delete[] tmp;
    }
}

void UpdateTextureRGBA( void* _tex, void* data, int w, int h )
{
    auto tex = (GLuint)(intptr_t)_tex;
    glBindTexture( GL_TEXTURE_2D, tex );
    glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, data );
}

void UpdateTextureRGBAMips( void* _tex, void** data, int* w, int* h, size_t mips )
{
    auto tex = (GLuint)(intptr_t)_tex;
    glBindTexture( GL_TEXTURE_2D, tex );
    for( size_t i=0; i<mips; i++ )
    {
        glTexImage2D( GL_TEXTURE_2D, i, GL_RGBA, w[i], h[i], 0, GL_RGBA, GL_UNSIGNED_BYTE, data[i] );
    }
}

}
