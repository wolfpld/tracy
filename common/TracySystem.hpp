#ifndef __TRACYSYSTEM_HPP__
#define __TRACYSYSTEM_HPP__

#include <stdint.h>
#include <thread>

namespace tracy
{

uint64_t GetThreadHandle();
void SetThreadName( std::thread& thread, const char* name );
const char* GetThreadName( uint64_t id );

}

#endif
