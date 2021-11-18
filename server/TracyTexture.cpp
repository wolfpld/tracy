#include <inttypes.h>

#include "../profiler/src/imgui_impl_opengl3_loader.h"
#include "TracyTexture.hpp"

#ifndef COMPRESSED_RGB_S3TC_DXT1_EXT
#  define COMPRESSED_RGB_S3TC_DXT1_EXT 0x83F0
#endif

namespace tracy
{

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
    glCompressedTexImage2D( GL_TEXTURE_2D, 0, COMPRESSED_RGB_S3TC_DXT1_EXT, w, h, 0, w * h / 2, data );
}

}
