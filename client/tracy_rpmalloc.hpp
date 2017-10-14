/* rpmalloc.h  -  Memory allocator  -  Public Domain  -  2016 Mattias Jansson / Rampant Pixels
 *
 * This library provides a cross-platform lock free thread caching malloc implementation in C11.
 * The latest source code is always available at
 *
 * https://github.com/rampantpixels/rpmalloc
 *
 * This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.
 *
 */

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__clang__) || defined(__GNUC__)
# define RPMALLOC_ATTRIBUTE __attribute__((__malloc__))
# define RPMALLOC_CALL
#elif defined(_MSC_VER)
# define RPMALLOC_ATTRIBUTE
# define RPMALLOC_CALL __declspec(restrict)
#else
# define RPMALLOC_ATTRIBUTE
# define RPMALLOC_CALL
#endif

//! Flag to rpaligned_realloc to not preserve content in reallocation
#define RPMALLOC_NO_PRESERVE    1

typedef struct rpmalloc_global_statistics_t {
	//! Current amount of virtual memory mapped (only if ENABLE_STATISTICS=1)
	size_t mapped;
	//! Current amount of memory in global caches for small and medium sizes (<64KiB)
	size_t cached;
	//! Curren amount of memory in global caches for large sizes (>=64KiB)
	size_t cached_large;
	//! Total amount of memory mapped (only if ENABLE_STATISTICS=1)
	size_t mapped_total;
	//! Total amount of memory unmapped (only if ENABLE_STATISTICS=1)
	size_t unmapped_total;
} rpmalloc_global_statistics_t;

typedef struct rpmalloc_thread_statistics_t {
	//! Amount of memory currently requested in allocations (only if ENABLE_STATISTICS=1)
	size_t requested;
	//! Amount of memory actually allocated in memory blocks (only if ENABLE_STATISTICS=1)
	size_t allocated;
	//! Current number of bytes available for allocation from active spans
	size_t active;
	//! Current number of bytes available in thread size class caches
	size_t sizecache;
	//! Current number of bytes available in thread span caches
	size_t spancache;
	//! Current number of bytes in pending deferred deallocations
	size_t deferred;
	//! Total number of bytes transitioned from thread cache to global cache
	size_t thread_to_global;
	//! Total number of bytes transitioned from global cache to thread cache
	size_t global_to_thread;
} rpmalloc_thread_statistics_t;

extern int
rpmalloc_initialize(void);

extern void
rpmalloc_finalize(void);

extern void
rpmalloc_thread_initialize(void);

extern void
rpmalloc_thread_finalize(void);

extern void
rpmalloc_thread_collect(void);

extern int
rpmalloc_is_thread_initialized(void);

extern void
rpmalloc_thread_statistics(rpmalloc_thread_statistics_t* stats);

extern void
rpmalloc_global_statistics(rpmalloc_global_statistics_t* stats);

extern RPMALLOC_CALL void*
rpmalloc(size_t size) RPMALLOC_ATTRIBUTE;

extern void
rpfree(void* ptr);

extern RPMALLOC_CALL void*
rpcalloc(size_t num, size_t size) RPMALLOC_ATTRIBUTE;

extern void*
rprealloc(void* ptr, size_t size);

extern void*
rpaligned_realloc(void* ptr, size_t alignment, size_t size, size_t oldsize, unsigned int flags);

extern RPMALLOC_CALL void*
rpaligned_alloc(size_t alignment, size_t size) RPMALLOC_ATTRIBUTE;

extern RPMALLOC_CALL void*
rpmemalign(size_t alignment, size_t size) RPMALLOC_ATTRIBUTE;

extern int
rpposix_memalign(void **memptr, size_t alignment, size_t size);

extern size_t
rpmalloc_usable_size(void* ptr);

#ifdef __cplusplus
}
#endif
