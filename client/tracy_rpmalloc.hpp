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

#include "../common/TracyApi.h"

namespace tracy
{

#if defined(__clang__) || defined(__GNUC__)
# define RPMALLOC_ATTRIBUTE __attribute__((__malloc__))
# define RPMALLOC_RESTRICT
# define RPMALLOC_CDECL
#elif defined(_MSC_VER)
# define RPMALLOC_ATTRIBUTE
# define RPMALLOC_RESTRICT __declspec(restrict)
# define RPMALLOC_CDECL __cdecl
#else
# define RPMALLOC_ATTRIBUTE
# define RPMALLOC_RESTRICT
# define RPMALLOC_CDECL
#endif

//! Flag to rpaligned_realloc to not preserve content in reallocation
#define RPMALLOC_NO_PRESERVE    1

typedef struct rpmalloc_global_statistics_t {
	//! Current amount of virtual memory mapped (only if ENABLE_STATISTICS=1)
	size_t mapped;
	//! Current amount of memory in global caches for small and medium sizes (<64KiB)
	size_t cached;
	//! Total amount of memory mapped (only if ENABLE_STATISTICS=1)
	size_t mapped_total;
	//! Total amount of memory unmapped (only if ENABLE_STATISTICS=1)
	size_t unmapped_total;
} rpmalloc_global_statistics_t;

typedef struct rpmalloc_thread_statistics_t {
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

typedef struct rpmalloc_config_t {
	//! Map memory pages for the given number of bytes. The returned address MUST be
	//  aligned to the rpmalloc span size, which will always be a power of two.
	//  Optionally the function can store an alignment offset in the offset variable
	//  in case it performs alignment and the returned pointer is offset from the
	//  actual start of the memory region due to this alignment. The alignment offset
	//  will be passed to the memory unmap function. The alignment offset MUST NOT be
	//  larger than 65535 (storable in an uint16_t), if it is you must use natural
	//  alignment to shift it into 16 bits.
	void* (*memory_map)(size_t size, size_t* offset);
	//! Unmap the memory pages starting at address and spanning the given number of bytes.
	//  If release is set to 1, the unmap is for an entire span range as returned by
	//  a previous call to memory_map and that the entire range should be released.
	//  If release is set to 0, the unmap is a partial decommit of a subset of the mapped
	//  memory range.
	void (*memory_unmap)(void* address, size_t size, size_t offset, int release);
	//! Size of memory pages. The page size MUST be a power of two in [512,16384] range
	//  (2^9 to 2^14) unless 0 - set to 0 to use system page size. All memory mapping
	//  requests to memory_map will be made with size set to a multiple of the page size.
	size_t page_size;
	//! Size of a span of memory pages. MUST be a multiple of page size, and in [4096,262144]
	//  range (unless 0 - set to 0 to use the default span size).
	size_t span_size;
	//! Number of spans to map at each request to map new virtual memory blocks. This can
	//  be used to minimize the system call overhead at the cost of virtual memory address
	//  space. The extra mapped pages will not be written until actually used, so physical
	//  committed memory should not be affected in the default implementation.
	size_t span_map_count;
	//! Debug callback if memory guards are enabled. Called if a memory overwrite is detected
	void (*memory_overwrite)(void* address);
} rpmalloc_config_t;

extern int
rpmalloc_initialize(void);

extern int
rpmalloc_initialize_config(const rpmalloc_config_t* config);

extern const rpmalloc_config_t*
rpmalloc_config(void);

extern void
rpmalloc_finalize(void);

void
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

TRACY_API RPMALLOC_RESTRICT void*
rpmalloc(size_t size) RPMALLOC_ATTRIBUTE;

TRACY_API void
rpfree(void* ptr);

extern RPMALLOC_RESTRICT void*
rpcalloc(size_t num, size_t size) RPMALLOC_ATTRIBUTE;

extern void*
rprealloc(void* ptr, size_t size);

extern void*
rpaligned_realloc(void* ptr, size_t alignment, size_t size, size_t oldsize, unsigned int flags);

extern RPMALLOC_RESTRICT void*
rpaligned_alloc(size_t alignment, size_t size) RPMALLOC_ATTRIBUTE;

extern RPMALLOC_RESTRICT void*
rpmemalign(size_t alignment, size_t size) RPMALLOC_ATTRIBUTE;

extern int
rpposix_memalign(void **memptr, size_t alignment, size_t size);

extern size_t
rpmalloc_usable_size(void* ptr);

}
