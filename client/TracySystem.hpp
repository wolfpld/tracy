#ifndef __TRACYSYSTEM_HPP__
#define __TRACYSYSTEM_HPP__

#include <thread>

namespace tracy
{

void SetThreadName( std::thread& thread, const char* name );

}

#endif
