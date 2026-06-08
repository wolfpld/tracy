#ifndef __TRACYALIGN_HPP__
#define __TRACYALIGN_HPP__

#include <string.h>
#include <type_traits>

#include "TracyForceInline.hpp"

namespace tracy
{

template<typename T>
tracy_force_inline T MemRead( const T* ptr )
{
    T val;
    memcpy( &val, ptr, sizeof( T ) );
    return val;
}

template<typename T, typename U>
tracy_force_inline void MemWrite( T* ptr, U val )
{
    static_assert( std::is_same<T, U>::value, "MemWrite type mismatch" );
    memcpy( (void*)ptr, &val, sizeof( T ) );
}

}

#endif
