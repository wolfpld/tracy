#ifndef __TRACYTEXTURE_HPP__
#define __TRACYTEXTURE_HPP__

#include <functional>

namespace tracy
{

void InitTexture();
void* MakeTexture( bool zigzag = false );
void FreeTexture( void* tex, void(*runOnMainThread)(const std::function<void()>&, bool) );
void UpdateTexture( void* tex, const char* data, int w, int h );
void UpdateTextureRGBA( void* tex, void* data, int w, int h );
void UpdateTextureRGBAMips( void* tex, void** data, int* w, int* h, size_t mips );

}

#endif
