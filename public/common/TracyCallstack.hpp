#ifndef __TRACYCALLSTACK_HPP__
#define __TRACYCALLSTACK_HPP__

#include <stdint.h>

#include "../common/TracyApi.h"
#include "../common/TracyForceInline.hpp"
#include "TracyCallstack.h"

namespace tracy
{

enum DecodeCallStackPtrStatusFlags : uint8_t
{
    Success = 0,
    ModuleMissing = 1 << 0,
    SymbolMissing = 1 << 1,

    ErrorMask = 0b11,

    NewModuleFound = 1 << 2,
        
    Count
};

using DecodeCallStackPtrStatus = uint8_t;
enum struct ImageDebugFormatId : uint8_t
{
    NoDebugFormat,
    PdbDebugFormat,
    GNUDebugFormat,
    ElfDebugFormat
};

struct ImageDebugInfo
{
    ImageDebugFormatId debugFormat;
    uint32_t debugDataSize;
    uint8_t* debugData;
};

struct ImageEntry
{
    uint64_t start;
    uint64_t end;
    char* name;
    char* path;
 
    ImageDebugInfo imageDebugInfo;
};
}

#ifndef TRACY_HAS_CALLSTACK

namespace tracy
{
static constexpr bool has_callstack() { return false; }
static tracy_force_inline void* Callstack( int32_t /*depth*/ ) { return nullptr; }
inline void PreventSymbolResolution() { }
}

#else

#if TRACY_HAS_CALLSTACK == 2 || TRACY_HAS_CALLSTACK == 5
#  include <unwind.h>
#elif TRACY_HAS_CALLSTACK >= 3
#  ifdef TRACY_LIBUNWIND_BACKTRACE
     // libunwind is, in general, significantly faster than execinfo based backtraces
#    define UNW_LOCAL_ONLY
#    include <libunwind.h>
#  else
#    include <execinfo.h>
#  endif
#endif

#ifdef TRACY_DEBUGINFOD
#  include <elfutils/debuginfod.h>
#endif

#include <assert.h>
#include <stdint.h>
#include <mutex>

#include "../common/TracyAlloc.hpp"
#include "../common/TracyFastVector.hpp"

namespace tracy
{

static constexpr bool has_callstack() { return true; }


struct CallstackSymbolData
{
    const char* file;
    uint32_t line;
    bool needFree;
    uint64_t symAddr;
};

struct CallstackEntry
{
    const char* name;
    const char* file;
    uint32_t line;
    uint32_t symLen;
    uint64_t symAddr; // Relative address
};

struct CallstackEntryData
{
    const CallstackEntry* data;
    uint8_t size;
    const char* imageName;
};


void PreventSymbolResolution();
std::recursive_mutex& GetModuleCacheMutexForRead();
const ImageEntry* GetImageEntryFromPtr( uint64_t ptr );

CallstackSymbolData DecodeSymbolAddress( uint64_t ptr );
const char* DecodeCallstackPtrFast( uint64_t ptr );
CallstackEntryData DecodeCallstackPtr( uint64_t ptr , DecodeCallStackPtrStatus* _decodeCallStackPtrStatus );


void InitCallstack();
void InitCallstackCritical();
void EndCallstack();
const char* GetKernelModulePath( uint64_t addr );

void CacheImageAndLoadDebugInfo( ImageEntry& imageEntry, bool loadDebugInfo );
const FastVector<ImageEntry>* GetUserImageInfos();
const FastVector<ImageEntry>* GetKernelImageInfos();


#ifdef TRACY_DEBUGINFOD
const uint8_t* GetBuildIdForImage( const char* image, size_t& size );
debuginfod_client* GetDebuginfodClient();
#endif

#if TRACY_HAS_CALLSTACK == 1

extern "C"
{
    TRACY_API unsigned long ___tracy_RtlWalkFrameChain( void**, unsigned long, unsigned long );
}

static tracy_force_inline void* Callstack( int32_t depth )
{
    assert( depth >= 1 && depth < 63 );
    auto trace = (uintptr_t*)tracy_malloc( ( 1 + depth ) * sizeof( uintptr_t ) );
    const auto num = ___tracy_RtlWalkFrameChain( (void**)( trace + 1 ), depth, 0 );
    *trace = num;
    return trace;
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

static tracy_force_inline void* Callstack( int32_t depth )
{
    assert( depth >= 1 && depth < 63 );

    auto trace = (uintptr_t*)tracy_malloc( ( 1 + depth ) * sizeof( uintptr_t ) );
    BacktraceState state = { (void**)(trace+1), (void**)(trace+1+depth) };
    _Unwind_Backtrace( tracy_unwind_callback, &state );

    *trace = (uintptr_t*)state.current - trace + 1;

    return trace;
}

#elif TRACY_HAS_CALLSTACK == 3 || TRACY_HAS_CALLSTACK == 4 || TRACY_HAS_CALLSTACK == 6

static tracy_force_inline void* Callstack( int32_t depth )
{
    assert( depth >= 1 );

    auto trace = (uintptr_t*)tracy_malloc( ( 1 + (size_t)depth ) * sizeof( uintptr_t ) );

#ifdef TRACY_LIBUNWIND_BACKTRACE
    size_t num =  unw_backtrace( (void**)(trace+1), depth );
#else
    const auto num = (size_t)backtrace( (void**)(trace+1), depth );
#endif

    *trace = num;

    return trace;
}

#endif

}

#endif

#endif
