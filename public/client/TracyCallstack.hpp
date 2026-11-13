#ifndef __TRACYCALLSTACK_HPP__
#define __TRACYCALLSTACK_HPP__

#include <stdint.h>

#include "../common/TracyApi.h"
#include "../common/TracyForceInline.hpp"
#include "TracyCallstack.h"

// External target API: desktop Linux only. The tracy-monitor that drives
// it builds for Linux x86_64/aarch64 only, and Android, although __linux__,
// lacks process_vm_readv on 32-bit ABIs.
#if defined(__linux__) && !defined(__ANDROID__) && defined(TRACY_HAS_CALLSTACK)
#  define TRACY_HAS_EXTERNAL_TARGET
#endif

namespace tracy
{

// Address to store for a callstack frame that is suspended in a call, given the return address reported by the unwinder.
// It lies inside the call instruction, so that the code that runs after the call returns is not attributed to the frame.
// See the contract in TracyCallstack.h. Frames that were interrupted (sample leaf, signal frame) must not go through it.
static constexpr tracy_force_inline uint64_t CallstackLookupAddress( uint64_t returnAddress )
{
#if defined __arm__ || defined _M_ARM
    // The unwinders strip the Thumb bit, but the raw perf callchain does not: without this, R-1 would be the start of the next instruction.
    returnAddress &= ~uint64_t( 1 );
#endif
    return returnAddress - 1;
}

struct ImageEntry
{
    uint64_t m_startAddress = 0;
    uint64_t m_endAddress = 0;
    char* m_name = nullptr;
    char* m_path = nullptr;
};

}

#ifndef TRACY_HAS_CALLSTACK

namespace tracy
{
static constexpr bool has_callstack() { return false; }
static tracy_force_inline void* Callstack( int32_t /*depth*/ ) { return nullptr; }
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

#include <stdint.h>

#include "../common/TracyAlloc.hpp"
#include "../common/TracyAssert.hpp"

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
    uint64_t symAddr;
};

struct CallstackEntryData
{
    const CallstackEntry* data;
    uint8_t size;
    const char* imageName;
};

CallstackSymbolData DecodeSymbolAddress( uint64_t ptr );
const char* DecodeCallstackPtrFast( uint64_t ptr );
CallstackEntryData DecodeCallstackPtr( uint64_t ptr );
void InitCallstack();
void InitCallstackCritical();
void EndCallstack();
const char* GetKernelModulePath( uint64_t addr );

#ifdef TRACY_HAS_EXTERNAL_TARGET
bool InitExternalTarget( pid_t targetPid );
uint32_t GetExternalTargetPid();
const char* GetExternalTargetName();
uint64_t GetExternalTargetExeTime();

size_t ReadExternalTargetMemory( uint64_t addr, uint32_t size, char* buf );
#endif

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
    TRACY_ASSERT( depth >= 1 && depth < 63 );
    auto trace = (uintptr_t*)tracy_malloc( ( 1 + depth ) * sizeof( uintptr_t ) );
    const auto num = ___tracy_RtlWalkFrameChain( (void**)( trace + 1 ), depth, 0 );
    // Every frame is suspended in a call (the first one is in the caller of RtlWalkFrameChain), they are all return addresses.
    // DbgHelp looks addresses up as is (SymFromAddr, SymGetLineFromAddr64, SymQueryInlineTrace), it does not compensate.
    for( size_t i=1; i<=num; i++ ) trace[i] = (uintptr_t)CallstackLookupAddress( trace[i] );
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
    // A frame that is suspended in a call reports the return address, which has to be moved back into the call.
    // A frame that was interrupted (a signal frame) reports the exact address ("before the instruction"), which is kept.
    int ipBeforeInsn = 0;
    uintptr_t pc = _Unwind_GetIPInfo( ctx, &ipBeforeInsn );
    if( pc )
    {
        if( state->current == state->end ) return _URC_END_OF_STACK;
        if( !ipBeforeInsn ) pc = (uintptr_t)CallstackLookupAddress( pc );
        *state->current++ = (void*)pc;
    }
    return _URC_NO_REASON;
}

static tracy_force_inline void* Callstack( int32_t depth )
{
    TRACY_ASSERT( depth >= 1 && depth < 63 );

    auto trace = (uintptr_t*)tracy_malloc( ( 1 + depth ) * sizeof( uintptr_t ) );
    BacktraceState state = { (void**)(trace+1), (void**)(trace+1+depth) };
    _Unwind_Backtrace( tracy_unwind_callback, &state );

    *trace = (uintptr_t*)state.current - trace + 1;

    return trace;
}

#elif TRACY_HAS_CALLSTACK == 3 || TRACY_HAS_CALLSTACK == 4 || TRACY_HAS_CALLSTACK == 6

static tracy_force_inline void* Callstack( int32_t depth )
{
    TRACY_ASSERT( depth >= 1 );

    auto trace = (uintptr_t*)tracy_malloc( ( 1 + (size_t)depth ) * sizeof( uintptr_t ) );

#ifdef TRACY_LIBUNWIND_BACKTRACE
    size_t num =  unw_backtrace( (void**)(trace+1), depth );
#else
    const auto num = (size_t)backtrace( (void**)(trace+1), depth );
#endif

    // These unwinders give no information on signal frames: every address is taken as a return address.
    for( size_t i=1; i<=num; i++ )
    {
        if( trace[i] != 0 ) trace[i] = (uintptr_t)CallstackLookupAddress( trace[i] );
    }

    *trace = num;

    return trace;
}

#endif

}

#endif

#endif
