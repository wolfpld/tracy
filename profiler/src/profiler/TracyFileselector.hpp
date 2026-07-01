#ifndef __TRACYFILESELECTOR_HPP__
#define __TRACYFILESELECTOR_HPP__

#include <stddef.h>
#include <functional>

namespace tracy::Fileselector
{

void Init( size_t type, void* handle );
void Shutdown();
bool HasFailed();

void OpenFile( const char* ext, const char* desc, const std::function<void(const char*)>& callback );
void SaveFile( const char* ext, const char* desc, const std::function<void(const char*)>& callback );

}

#endif
