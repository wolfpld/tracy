#ifndef __TRACYTEXTURE_HPP__
#define __TRACYTEXTURE_HPP__

#include <functional>

namespace tracy
{

void InitTexture();
void* MakeTexture();
void FreeTexture( void* tex, void(*runOnMainThread)(std::function<void()>, bool) );
void UpdateTexture( void* tex, const char* data, int w, int h );
void UpdateTextureRGBA( void* tex, void* data, int w, int h );

}

#endif
