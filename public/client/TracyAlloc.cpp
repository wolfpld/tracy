#include "../common/TracyAlloc.hpp"

#if defined( TRACY_DEFAULT_MEMORY_PROFLER )/* && defined( TRACY_ON_DEMAND )*/
#  if __has_include( <dlfcn.h>)
#    include "../client/TracyProfiler.hpp"
#    include <dlfcn.h>
#    define TRACY_ENABLE_DEFAULT_MEMORY_PROFLER
#  endif
#endif

#ifndef TRACY_ENABLE_DEFAULT_MEMORY_PROFLER
namespace
{
auto _malloc = &malloc;
auto _free = &free;
auto _calloc = &calloc;
auto _realloc = &realloc;
} // namespace {
#else
namespace
{

inline void* _malloc( size_t size )
{
    static auto malloc_ = reinterpret_cast<void* (*)( size_t )>( dlsym( RTLD_NEXT, "malloc" ) );
    return malloc_( size );
}
inline void _free( void* ptr )
{
    static auto free_ = reinterpret_cast<void ( * )( void* )>( dlsym( RTLD_NEXT, "free" ) );
    free_( ptr );
}
inline void* _calloc( size_t nmemb, size_t size )
{
    static auto calloc_ = reinterpret_cast<void* (*)( size_t, size_t )>( dlsym( RTLD_NEXT, "calloc" ) );
    return calloc_( nmemb, size );
}

inline void* _realloc( void* ptr, size_t size )
{
    static auto realloc_ = reinterpret_cast<void* (*)( void*, size_t )>( dlsym( RTLD_NEXT, "realloc" ) );
    return realloc_( ptr, size );
}

} // namespace {

extern "C"
{
    void* malloc( size_t size )
    {
        if( tracy::DirectAlloc::s_direct )
            return _malloc( size );
        tracy::DirectAlloc locker;
        auto _ptr = _malloc( size );
        tracy::Profiler::MemAllocCallstack( _ptr, size, 50, false );
        return _ptr;
    }

    void free( void* ptr )
    {
        if( tracy::DirectAlloc::s_direct )
            return _free( ptr );
        tracy::DirectAlloc locker;
        if( ptr )
            tracy::Profiler::MemFreeCallstack( ptr, 50, false );
        _free( ptr );
    }

    void* calloc( size_t nmemb, size_t size )
    {
        if( tracy::DirectAlloc::s_direct )
            return _calloc( nmemb, size );
        tracy::DirectAlloc locker;
        auto _ptr = _calloc( nmemb, size );
        tracy::Profiler::MemAllocCallstack( _ptr, nmemb * size, 50, false );
        return _ptr;
    }

    void* realloc( void* ptr, size_t size )
    {
        if( tracy::DirectAlloc::s_direct )
            return _realloc( ptr, size );
        tracy::DirectAlloc locker;
        if( ptr )
            tracy::Profiler::MemFreeCallstack( ptr, 50, false );
        auto _ptr = _realloc( ptr, size );
        tracy::Profiler::MemAllocCallstack( _ptr, size, 50, false );
        return _ptr;
    }
} // extern "C" {
#endif

#ifdef TRACY_USE_RPMALLOC

#  include <atomic>

#  include "../common/TracyForceInline.hpp"
#  include "../common/TracyYield.hpp"
#endif

namespace tracy
{

thread_local int DirectAlloc::s_direct = 0;

#ifdef TRACY_USE_RPMALLOC
extern thread_local bool RpThreadInitDone;
extern std::atomic<int> RpInitDone;
extern std::atomic<int> RpInitLock;

tracy_no_inline static void InitRpmallocPlumbing()
{
    const auto done = RpInitDone.load( std::memory_order_acquire );
    if( !done )
    {
        int expected = 0;
        while( !RpInitLock.compare_exchange_weak( expected, 1, std::memory_order_release, std::memory_order_relaxed ) )
        {
            expected = 0;
            YieldThread();
        }
        const auto done = RpInitDone.load( std::memory_order_acquire );
        if( !done )
        {
            rpmalloc_initialize();
            RpInitDone.store( 1, std::memory_order_release );
        }
        RpInitLock.store( 0, std::memory_order_release );
    }
    rpmalloc_thread_initialize();
    RpThreadInitDone = true;
}

TRACY_API void InitRpmalloc()
{
    if( !RpThreadInitDone ) InitRpmallocPlumbing();
}
#endif

TRACY_API void* tracy_malloc( size_t size )
{
#  ifdef TRACY_USE_RPMALLOC
    InitRpmalloc();
    return rpmalloc( size );
#  else
    return _malloc( size );
#  endif
}

TRACY_API void* tracy_malloc_fast( size_t size )
{
#  ifdef TRACY_USE_RPMALLOC
    return rpmalloc( size );
#  else
    return _malloc( size );
#  endif
}

TRACY_API void tracy_free( void* ptr )
{
#  ifdef TRACY_USE_RPMALLOC
    InitRpmalloc();
    rpfree( ptr );
#  else
    _free( ptr );
#  endif
}

TRACY_API void tracy_free_fast( void* ptr )
{
#  ifdef TRACY_USE_RPMALLOC
    rpfree( ptr );
#  else
    _free( ptr );
#  endif
}

TRACY_API void* tracy_realloc( void* ptr, size_t size )
{
#  ifdef TRACY_USE_RPMALLOC
    InitRpmalloc();
    return rprealloc( ptr, size );
#  else
    return _realloc( ptr, size );
#  endif
}

} // namespace tracy
