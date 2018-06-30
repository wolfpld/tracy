#ifndef __TRACYALLOC_HPP__
#define __TRACYALLOC_HPP__

#include <cstdlib>

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

}

#endif
