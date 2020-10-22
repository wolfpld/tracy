#ifndef __TRACYALLOC_HPP__
#define __TRACYALLOC_HPP__

#include <stdlib.h>

#ifdef TRACY_ENABLE
#  include "../client/tracy_rpmalloc.hpp"
#endif

namespace tracy
{

static inline void* tracy_malloc( size_t size )
{
#ifdef TRACY_ENABLE
    return rpmalloc( size );
#else
    return malloc( size );
#endif
}

static inline void tracy_free( void* ptr )
{
#ifdef TRACY_ENABLE
    rpfree( ptr );
#else
    free( ptr );
#endif
}

static inline void* tracy_realloc( void* ptr, size_t size )
{
#ifdef TRACY_ENABLE
    return rprealloc( ptr, size );
#else
    return realloc( ptr, size );
#endif
}

}

#endif
