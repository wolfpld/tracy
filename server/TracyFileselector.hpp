#ifndef __TRACYFILESELECTOR_HPP__
#define __TRACYFILESELECTOR_HPP__

#include <string>

namespace tracy::Fileselector
{

void Init();
void Shutdown();

std::string OpenFile( const char* ext, const char* desc );
std::string SaveFile( const char* ext, const char* desc );

}

#endif
