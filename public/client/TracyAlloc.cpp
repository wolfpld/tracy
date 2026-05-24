#include "../common/TracyAlloc.hpp"

#if defined TRACY_USE_RPMALLOC || defined TRACY_HAS_CUSTOM_ALLOCATOR

#include <atomic>

#include "../common/TracyForceInline.hpp"
#include "../common/TracyYield.hpp"

namespace tracy
{

extern thread_local bool RpThreadInitDone;
extern std::atomic<int> RpInitDone;
extern std::atomic<int> RpInitLock;

tracy_no_inline static void InitAllocatorPlumbing()
{
    const auto done = RpInitDone.load( std::memory_order_acquire );
    if( !done )
    {
        int expected = 0;
        while( !RpInitLock.compare_exchange_weak( expected, 1, std::memory_order_release, std::memory_order_relaxed ) ) { expected = 0; YieldThread(); }
        const auto done = RpInitDone.load( std::memory_order_acquire );
        if( !done )
        {
#if defined TRACY_HAS_CUSTOM_ALLOCATOR
            PlatformAllocatorInit();
#else
            rpmalloc_initialize();
#endif
            RpInitDone.store( 1, std::memory_order_release );
        }
        RpInitLock.store( 0, std::memory_order_release );
    }
#if defined TRACY_HAS_CUSTOM_ALLOCATOR
    PlatformAllocatorThreadInit();
#else
    rpmalloc_thread_initialize();
#endif
    RpThreadInitDone = true;
}

TRACY_API void InitAllocator()
{
    if( !RpThreadInitDone ) InitAllocatorPlumbing();
}

}

#endif
