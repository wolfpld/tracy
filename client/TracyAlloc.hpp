#ifndef __TRACYALLOC_HPP__
#define __TRACYALLOC_HPP__

#include "tracy_rpmalloc.hpp"

namespace tracy
{

static inline void* tracy_malloc( size_t size )
{
    return rpmalloc( size );
}

static inline void tracy_free( void* ptr )
{
    rpfree( ptr );
}

}

#endif
