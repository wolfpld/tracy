#ifndef __TRACYALLOC_HPP__
#define __TRACYALLOC_HPP__

#include <stdlib.h>

#include "TracyApi.h"
#if defined TRACY_ENABLE && !defined __EMSCRIPTEN__
#  include "TracyForceInline.hpp"
#  include "../client/tracy_rpmalloc.hpp"
#  define TRACY_USE_RPMALLOC
#endif

namespace tracy
{

struct DirectAlloc
{
    inline DirectAlloc() { ++s_direct; }
    inline ~DirectAlloc() { --s_direct; }
    static thread_local int s_direct;
};

#ifdef TRACY_USE_RPMALLOC
TRACY_API void InitRpmalloc();
#else
static inline void InitRpmalloc() {}
#endif

TRACY_API void* tracy_malloc( size_t size );
TRACY_API void* tracy_malloc_fast( size_t size );
TRACY_API void tracy_free( void* ptr );
TRACY_API void tracy_free_fast( void* ptr );
TRACY_API void* tracy_realloc( void* ptr, size_t size );

}

#endif
