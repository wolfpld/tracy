#ifndef __TRACYFILESELECTOR_HPP__
#define __TRACYFILESELECTOR_HPP__

#include <functional>

namespace tracy::Fileselector
{

void Init();
void Shutdown();

// Will return false if file selector cannot be presented to the user.
bool OpenFile( const char* ext, const char* desc, std::function<void(const char*)> callback );
bool SaveFile( const char* ext, const char* desc, std::function<void(const char*)> callback );

}

#endif
