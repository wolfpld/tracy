// Template implementations of the tracy::Platform* hooks. Pair with the
// platform header (see CustomPlatform.h) and link this into your final
// binary.

#include <stdlib.h>
#include <string.h>

#include "CustomPlatform.h"

namespace tracy
{

uint32_t PlatformGetThreadId()
{
    return 0;
}

void PlatformGetHostname( char* buf, size_t size )
{
    const char* placeholder = "(?)";
    if( size == 0 ) return;
    const size_t n = strlen( placeholder );
    const size_t copy = n < size - 1 ? n : size - 1;
    memcpy( buf, placeholder, copy );
    buf[copy] = '\0';
}

const char* PlatformGetUserLogin()
{
    return "(?)";
}

const char* PlatformGetUserFullName()
{
    return nullptr;
}

bool PlatformSafeMemcpy( void* dst, const void* src, size_t size )
{
    // Stub: report failure so Tracy skips the snapshot. Real impls use SEH
    // on Win32, pipe(2) on POSIX, or an equivalent probe-and-copy primitive.
    (void)dst; (void)src; (void)size;
    return false;
}

// Stubs forward to the C runtime. Swap in the allocator you actually want.

void* PlatformMalloc( size_t size )                { return malloc( size ); }
void  PlatformFree( void* ptr )                    { free( ptr ); }
void* PlatformRealloc( void* ptr, size_t size )    { return realloc( ptr, size ); }

void PlatformAllocatorInit()         {}
void PlatformAllocatorThreadInit()   {}
void PlatformAllocatorFinalize()     {}
void PlatformAllocatorThreadFinalize(){}

}
