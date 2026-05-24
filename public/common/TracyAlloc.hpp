#ifndef __TRACYALLOC_HPP__
#define __TRACYALLOC_HPP__

#include <stdlib.h>

#ifdef TRACY_PLATFORM_HEADER
#  include TRACY_PLATFORM_HEADER
#endif

#if defined TRACY_ENABLE && !defined __EMSCRIPTEN__
#  include "TracyApi.h"
#  include "TracyForceInline.hpp"
#  if !defined TRACY_HAS_CUSTOM_ALLOCATOR
#    include "../client/tracy_rpmalloc.hpp"
#    define TRACY_USE_RPMALLOC
#  endif
#endif

namespace tracy
{

#if defined TRACY_USE_RPMALLOC || defined TRACY_HAS_CUSTOM_ALLOCATOR
TRACY_API void InitAllocator();
#else
static inline void InitAllocator() {}
#endif

static inline void* tracy_malloc( size_t size )
{
#if defined TRACY_HAS_CUSTOM_ALLOCATOR
    InitAllocator();
    return PlatformMalloc( size );
#elif defined TRACY_USE_RPMALLOC
    InitAllocator();
    return rpmalloc( size );
#else
    return malloc( size );
#endif
}

static inline void* tracy_malloc_fast( size_t size )
{
#if defined TRACY_HAS_CUSTOM_ALLOCATOR
    return PlatformMalloc( size );
#elif defined TRACY_USE_RPMALLOC
    return rpmalloc( size );
#else
    return malloc( size );
#endif
}

static inline void tracy_free( void* ptr )
{
#if defined TRACY_HAS_CUSTOM_ALLOCATOR
    InitAllocator();
    PlatformFree( ptr );
#elif defined TRACY_USE_RPMALLOC
    InitAllocator();
    rpfree( ptr );
#else
    free( ptr );
#endif
}

static inline void tracy_free_fast( void* ptr )
{
#if defined TRACY_HAS_CUSTOM_ALLOCATOR
    PlatformFree( ptr );
#elif defined TRACY_USE_RPMALLOC
    rpfree( ptr );
#else
    free( ptr );
#endif
}

static inline void* tracy_realloc( void* ptr, size_t size )
{
#if defined TRACY_HAS_CUSTOM_ALLOCATOR
    InitAllocator();
    return PlatformRealloc( ptr, size );
#elif defined TRACY_USE_RPMALLOC
    InitAllocator();
    return rprealloc( ptr, size );
#else
    return realloc( ptr, size );
#endif
}

}

#endif
