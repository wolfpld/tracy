#include <inttypes.h>

#ifdef __EMSCRIPTEN__
#  include <emscripten/html5.h>
#  include <GLES2/gl2.h>
#else
#  include "../profiler/src/imgui/imgui_impl_opengl3_loader.h"
#endif
#include "TracyTexture.hpp"

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

void* MakeTexture()
{
    GLuint tex;
    glGenTextures( 1, &tex );
    glBindTexture( GL_TEXTURE_2D, tex );
    glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR );
    glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR );
    glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
    return (void*)(intptr_t)tex;
}

void FreeTexture( void* _tex, void(*runOnMainThread)(std::function<void()>, bool) )
{
    auto tex = (GLuint)(intptr_t)_tex;
    runOnMainThread( [tex] { glDeleteTextures( 1, &tex ); }, false );
}

void UpdateTexture( void* _tex, const char* data, int w, int h )
{
    auto tex = (GLuint)(intptr_t)_tex;
    glBindTexture( GL_TEXTURE_2D, tex );
    if( s_hardwareS3tc )
    {
        glCompressedTexImage2D( GL_TEXTURE_2D, 0, COMPRESSED_RGB_S3TC_DXT1_EXT, w, h, 0, w * h / 2, data );
    }
}

void UpdateTextureRGBA( void* _tex, void* data, int w, int h )
{
    auto tex = (GLuint)(intptr_t)_tex;
    glBindTexture( GL_TEXTURE_2D, tex );
    glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, data );
}

}
