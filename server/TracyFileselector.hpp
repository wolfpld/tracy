#ifndef __TRACYFILESELECTOR_HPP__
#define __TRACYFILESELECTOR_HPP__

#include <functional>

namespace tracy::Fileselector
{

void Init();
void Shutdown();
bool HasFailed();

void OpenFile( const char* ext, const char* desc, std::function<void(const char*)> callback );
void SaveFile( const char* ext, const char* desc, std::function<void(const char*)> callback );

}

#endif
