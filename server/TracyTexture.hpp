#ifndef __TRACYTEXTURE_HPP__
#define __TRACYTEXTURE_HPP__

namespace tracy
{

void* MakeTexture();
void FreeTexture( void* tex );
void UpdateTexture( void* tex, const char* data, int w, int h );

}

#endif
