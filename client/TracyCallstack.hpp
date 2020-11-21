#ifndef __TRACYCALLSTACK_HPP__
#define __TRACYCALLSTACK_HPP__

#include "../common/TracyApi.h"
#include "TracyCallstack.h"

#if TRACY_HAS_CALLSTACK == 2 || TRACY_HAS_CALLSTACK == 5
#  include <unwind.h>
#elif TRACY_HAS_CALLSTACK >= 3
#  include <execinfo.h>
#endif

#ifdef __ANDROID__
#  include <sys/mman.h>
#  include <stdio.h>
#  include <stdint.h>
#  include <algorithm>
#  include <vector>
#endif

#ifdef TRACY_HAS_CALLSTACK

#include <assert.h>
#include <stdint.h>

#include "../common/TracyAlloc.hpp"
#include "../common/TracyForceInline.hpp"

namespace tracy
{

struct CallstackSymbolData
{
    const char* file;
    uint32_t line;
    bool needFree;
};

struct CallstackEntry
{
    const char* name;
    const char* file;
    uint32_t line;
    uint32_t symLen;
    uint64_t symAddr;
};

struct CallstackEntryData
{
    const CallstackEntry* data;
    uint8_t size;
    const char* imageName;
};

CallstackSymbolData DecodeSymbolAddress( uint64_t ptr );
CallstackSymbolData DecodeCodeAddress( uint64_t ptr );
const char* DecodeCallstackPtrFast( uint64_t ptr );
CallstackEntryData DecodeCallstackPtr( uint64_t ptr );
void InitCallstack();

#if TRACY_HAS_CALLSTACK == 1

TRACY_API uintptr_t* CallTrace( int depth );

static tracy_force_inline void* Callstack( int depth )
{
    assert( depth >= 1 && depth < 63 );
    return CallTrace( depth );
}

#elif TRACY_HAS_CALLSTACK == 2 || TRACY_HAS_CALLSTACK == 5

struct BacktraceState
{
    void** current;
    void** end;
};

static _Unwind_Reason_Code tracy_unwind_callback( struct _Unwind_Context* ctx, void* arg )
{
    auto state = (BacktraceState*)arg;
    uintptr_t pc = _Unwind_GetIP( ctx );
    if( pc )
    {
        if( state->current == state->end ) return _URC_END_OF_STACK;
        *state->current++ = (void*)pc;
    }
    return _URC_NO_REASON;
}

static tracy_force_inline void* Callstack( int depth )
{
    assert( depth >= 1 && depth < 63 );

    auto trace = (uintptr_t*)tracy_malloc( ( 1 + depth ) * sizeof( uintptr_t ) );
    BacktraceState state = { (void**)(trace+1), (void**)(trace+1+depth) };
    _Unwind_Backtrace( tracy_unwind_callback, &state );

    *trace = (uintptr_t*)state.current - trace + 1;

    return trace;
}

#elif TRACY_HAS_CALLSTACK == 3 || TRACY_HAS_CALLSTACK == 4 || TRACY_HAS_CALLSTACK == 6

static tracy_force_inline void* Callstack( int depth )
{
    assert( depth >= 1 );

    auto trace = (uintptr_t*)tracy_malloc( ( 1 + depth ) * sizeof( uintptr_t ) );
    const auto num = backtrace( (void**)(trace+1), depth );
    *trace = num;

    return trace;
}

#endif

}

#endif

#ifdef __ANDROID__
namespace tracy {
// Implementation of EnsureReadable, a helper to ensure that we can read symbols code.
// This is so far only needed on Android, where it is common for libraries to be mapped
// with only executable, not readable, permissions. Typical example (line from /proc/self/maps):
/*
746b63b000-746b6dc000 --xp 00042000 07:48 35                             /apex/com.android.runtime/lib64/bionic/libc.so
*/
// See https://github.com/wolfpld/tracy/issues/125 .
// To work around this, we parse /proc/self/maps and we use mprotect to set read permissions
// on any mappings that contain symbols addresses hit by HandleSymbolCodeQuery.

// Holds some information about a single memory mapping.
struct MappingInfo {
    // Start of address range. Inclusive.
    uintptr_t start_address;
    // End of address range. Exclusive, so the mapping is the half-open interval
    // [start, end) and its length in bytes is `end - start`. As in /proc/self/maps.
    uintptr_t end_address;
    // Read/Write/Executable permissions.
    bool perm_r, perm_w, perm_x;
};

// Internal implementation helper for LookUpMapping(address).
//
// Parses /proc/self/maps returning a vector<MappingInfo>.
// /proc/self/maps is assumed to be sorted by ascending address, so the resulting
// vector is sorted by ascending address too.
inline std::vector<MappingInfo> ParseMappings()
{
    std::vector<MappingInfo> result;
    FILE* file = fopen( "/proc/self/maps", "r" );
    if( !file ) return result;
    char line[1024];
    while( fgets( line, sizeof( line ), file ) )
    {
        uintptr_t start_addr;
        uintptr_t end_addr;
        if( sscanf( line, "%lx-%lx", &start_addr, &end_addr ) != 2 ) continue;
        char* first_space = strchr( line, ' ' );
        if( !first_space ) continue;
        char* perm = first_space + 1;
        char* second_space = strchr( perm, ' ' );
        if( !second_space || second_space - perm != 4 ) continue;
        result.emplace_back();
        auto& mapping = result.back();
        mapping.start_address = start_addr;
        mapping.end_address = end_addr;
        mapping.perm_r = perm[0] == 'r';
        mapping.perm_w = perm[1] == 'w';
        mapping.perm_x = perm[2] == 'x';
    }
    fclose( file );
    return result;
}

// Internal implementation helper for LookUpMapping(address).
//
// Takes as input an `address` and a
// known vector `mappings`, and returns a pointer to the MappingInfo
// describing the mapping that this address belongs to, or nullptr if
// the address isn't in `mappings`.
inline MappingInfo* LookUpMapping(std::vector<MappingInfo>& mappings, uintptr_t address)
{
    // We assume mappings to be sorted by address, as /proc/self/maps seems to be.
    // Construct a MappingInfo just for the purpose of using std::lower_bound.
    MappingInfo needle;
    needle.start_address = address;
    needle.end_address = address;
    // Comparison function for std::lower_bound. Returns true if all addresses in `m1`
    // are lower than all addresses in `m2`.
    auto Compare = []( const MappingInfo& m1, const MappingInfo& m2 ) {
        // '<=' because the address ranges are half-open intervals, [start, end).
        return m1.end_address <= m2.start_address;
    };
    auto iter = std::lower_bound( mappings.begin(), mappings.end(), needle, Compare );
    if( iter == mappings.end() || iter->end_address <= address) {
        return nullptr;
    }
    return &*iter;
}

// Internal implementation helper for EnsureReadable(address).
//
// Takes as input an `address` and returns a pointer to a MappingInfo
// describing the mapping that this address belongs to, or nullptr if
// the address isn't in any known mapping.
//
// This function is stateful and not reentrant (assumes to be called from)
// only one thread. It holds a vector of mappings parsed from /proc/self/maps.
//
// Attempts to react to mappings changes by re-parsing /proc/self/maps.
inline MappingInfo* LookUpMapping(uintptr_t address)
{
    // Static state managed by this function. Not constant, we mutate that state as
    // we turn some mappings readable. Initially parsed once here, updated as needed below.
    static std::vector<MappingInfo> s_mappings = ParseMappings();
    MappingInfo* mapping = LookUpMapping( s_mappings, address );
    if( mapping ) return mapping;

    // This address isn't in any known mapping. Try parsing again, maybe
    // mappings changed.
    s_mappings = ParseMappings();
    return LookUpMapping( s_mappings, address );
}

// Internal implementation helper for EnsureReadable(address).
//
// Attempts to make the specified `mapping` readable if it isn't already.
// Returns true if and only if the mapping is readable.
inline bool EnsureReadable( MappingInfo& mapping )
{
    if( mapping.perm_r )
    {
        // The mapping is already readable.
        return true;
    }
    int prot = PROT_READ;
    if( mapping.perm_w ) prot |= PROT_WRITE;
    if( mapping.perm_x ) prot |= PROT_EXEC;
    if( mprotect( reinterpret_cast<void*>( mapping.start_address ),
                  mapping.end_address - mapping.start_address, prot ) == -1 )
    {
        // Failed to make the mapping readable. Shouldn't happen, hasn't
        // been observed yet. If it happened in practice, we should consider
        // adding a bool to MappingInfo to track this to avoid retrying mprotect
        // everytime on such mappings.
        return false;
    }
    // The mapping is now readable. Update `mapping` so the next call will be fast.
    mapping.perm_r = true;
    return true;
}

// Attempts to set the read permission on the entire mapping containing the
// specified address.
inline bool EnsureReadable( uintptr_t address )
{
    MappingInfo* mapping = LookUpMapping(address);
    return mapping && EnsureReadable( *mapping );
}

}  // namespace tracy
#endif  // defined __ANDROID__

#endif
