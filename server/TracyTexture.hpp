#ifndef __TRACYTEXTURE_HPP__
#define __TRACYTEXTURE_HPP__

#include <functional>

namespace tracy
{

void* MakeTexture();
void FreeTexture( void* tex, void(*runOnMainThread)(std::function<void()>, bool) );
void UpdateTexture( void* tex, const char* data, int w, int h );

}

#endif
