#ifndef __TRACYCALLSTACK_HPP__
#define __TRACYCALLSTACK_HPP__

#if defined _WIN32 || defined __CYGWIN__
#  define TRACY_HAS_CALLSTACK
extern "C"
{
    typedef unsigned long (__stdcall *t_RtlWalkFrameChain)( void**, unsigned long, unsigned long );
    extern t_RtlWalkFrameChain RtlWalkFrameChain;
}
#elif defined __ANDROID__
#  define TRACY_HAS_CALLSTACK
#  include <unwind.h>
#elif defined _GNU_SOURCE
#  define TRACY_HAS_CALLSTACK
#  include <execinfo.h>
#endif


#ifdef TRACY_HAS_CALLSTACK

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../common/TracyAlloc.hpp"
#include "../common/TracyForceInline.hpp"

namespace tracy
{

struct CallstackEntry
{
    const char* name;
    const char* file;
    uint32_t line;
};

CallstackEntry DecodeCallstackPtr( uint64_t ptr );

#if defined _WIN32 || defined __CYGWIN__

void InitCallstack();

static tracy_force_inline void* Callstack( int depth )
{
    assert( depth >= 1 && depth < 63 );

    auto trace = (uintptr_t*)tracy_malloc( ( 1 + depth ) * sizeof( uintptr_t ) );
    const auto num = RtlWalkFrameChain( (void**)( trace + 1 ), depth, 0 );
    *trace = num;

    return trace;
}

#elif defined __ANDROID__

static tracy_force_inline void InitCallstack() {}

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

#elif defined _GNU_SOURCE

static tracy_force_inline void InitCallstack() {}

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

#endif
