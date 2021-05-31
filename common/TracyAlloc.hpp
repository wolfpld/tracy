#ifndef __TRACYALLOC_HPP__
#define __TRACYALLOC_HPP__

#include <stdlib.h>

#ifdef TRACY_ENABLE
#  include <atomic>
#  include "TracyForceInline.hpp"
#  include "TracyYield.hpp"
#  include "../client/tracy_rpmalloc.hpp"
#endif

namespace tracy
{

#ifdef TRACY_ENABLE
extern std::atomic<int> RpInitDone;
extern std::atomic<int> RpInitLock;

namespace
{
static inline void InitRpmallocPlumbing()
{
    int expected = 0;
    while( !RpInitLock.compare_exchange_weak( expected, 1, std::memory_order_release, std::memory_order_relaxed ) ) { expected = 0; YieldThread(); }
    const auto done = RpInitDone.load( std::memory_order_acquire );
    if( !done )
    {
        rpmalloc_initialize();
        RpInitDone.store( 1, std::memory_order_release );
    }
    RpInitLock.store( 0, std::memory_order_release );
}

static tracy_force_inline void InitRpmalloc()
{
    const auto done = RpInitDone.load( std::memory_order_acquire );
    if( !done ) InitRpmallocPlumbing();
    rpmalloc_thread_initialize();
}
}
#endif

static inline void* tracy_malloc( size_t size )
{
#ifdef TRACY_ENABLE
    InitRpmalloc();
    return rpmalloc( size );
#else
    return malloc( size );
#endif
}

static inline void tracy_free( void* ptr )
{
#ifdef TRACY_ENABLE
    InitRpmalloc();
    rpfree( ptr );
#else
    free( ptr );
#endif
}

static inline void* tracy_realloc( void* ptr, size_t size )
{
#ifdef TRACY_ENABLE
    InitRpmalloc();
    return rprealloc( ptr, size );
#else
    return realloc( ptr, size );
#endif
}

}

#endif
