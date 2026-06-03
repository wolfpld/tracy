#ifndef __TRACYALIGN_HPP__
#define __TRACYALIGN_HPP__

#include <string.h>

#include "TracyForceInline.hpp"

namespace tracy
{

template<typename T>
tracy_force_inline T MemRead( const void* ptr )
{
    T val;
    memcpy( &val, ptr, sizeof( T ) );
    return val;
}

template<typename T>
tracy_force_inline void MemWrite( T* ptr, const T val )
{
    memcpy( (void*)ptr, &val, sizeof( T ) );
}

template<typename T, typename U>
tracy_force_inline void MemWrite( T* ptr, U val )
{
    static_assert( false, "type mismatch!" );
}

}

#endif
