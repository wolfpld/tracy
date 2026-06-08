// Template platform header for unsupported targets.
//
// Copy into your project, fill in the sections you need, and point Tracy at
// it via -DTRACY_PLATFORM_HEADER="\"my_platform.h\"". Provide the
// implementations in any TU linked into your final binary (see
// CustomPlatform.cpp).
//
// Use this only for the TRACY_HAS_CUSTOM_* hooks and matching Platform*
// declarations — don't set unrelated TRACY_* options here. Some are checked
// before this header is included, so the result would depend on which TU
// consulted them; set those at the build system level instead.
//
// For platform-specific features without a custom hook (call stacks,
// context switches, crash handling, system tracing, etc.), disable them at
// the build system level with the matching TRACY_NO_* macro.

#ifndef __MY_TRACY_PLATFORM_H__
#define __MY_TRACY_PLATFORM_H__

#include <stddef.h>
#include <stdint.h>

namespace tracy
{

// --- Thread id --------------------------------------------------------------
//
// Required if defaults in TracySystem.cpp  do not matches your platform.
// Note pthread_self() is NOT suitable, it returns a library handle, not a kernel id.
//#define TRACY_HAS_CUSTOM_THREAD_ID
uint32_t PlatformGetThreadId();


// --- User info --------------------------------------------------------------
//
// Identifies the machine and user in the trace header. Return placeholder
// strings (e.g. "(?)") from any of these if your platform has no equivalent
// notion.
//#define TRACY_HAS_CUSTOM_USER_INFO
void        PlatformGetHostname( char* buf, size_t size );
const char* PlatformGetUserLogin();
const char* PlatformGetUserFullName();


// --- Safe memory copy -------------------------------------------------------
//
// Tracy uses this to snapshot potentially-unmapped memory during sampling.
// Must not crash on unreadable input — return false instead. Plain memcpy()
// is NOT a valid implementation.
//#define TRACY_HAS_CUSTOM_SAFE_COPY
bool PlatformSafeMemcpy( void* dst, const void* src, size_t size );


// --- Allocator --------------------------------------------------------------
//
// Replaces Tracy's internal allocator. Drop in the system allocator, an
// in-house one, or any third-party allocator you like. Malloc/Free/Realloc
// must be thread-safe; ThreadInit is an optional prime, not a precondition.
// Finalize must also tear down the calling thread's per-thread state, the
// way rpmalloc_finalize() does — Tracy does not call ThreadFinalize for the
// shutdown thread before Finalize.
//#define TRACY_HAS_CUSTOM_ALLOCATOR
void* PlatformMalloc( size_t size );
void  PlatformFree( void* ptr );
void* PlatformRealloc( void* ptr, size_t size );
void  PlatformAllocatorInit();
void  PlatformAllocatorThreadInit();
void  PlatformAllocatorFinalize();
void  PlatformAllocatorThreadFinalize();

}

#endif
