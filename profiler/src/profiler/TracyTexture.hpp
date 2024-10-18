#ifndef __TRACYTEXTURE_HPP__
#define __TRACYTEXTURE_HPP__

#include <functional>
#include <imgui.h>

namespace tracy
{

void InitTexture();
ImTextureID MakeTexture( bool zigzag = false );
void FreeTexture( ImTextureID tex, void(*runOnMainThread)(const std::function<void()>&, bool) );
void UpdateTexture( ImTextureID tex, const char* data, int w, int h );
void UpdateTextureRGBA( ImTextureID tex, void* data, int w, int h );
void UpdateTextureRGBAMips( ImTextureID tex, void** data, int* w, int* h, size_t mips );

}

#endif
