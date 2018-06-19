#ifndef __TRACYCALLSTACK_HPP__
#define __TRACYCALLSTACK_HPP__

#ifdef _WIN32
#  define TRACY_HAS_CALLSTACK
#  ifndef MAXLONG
extern "C" __declspec(dllimport) unsigned short __stdcall RtlCaptureStackBackTrace( unsigned long, unsigned long, void**, unsigned long* );
#  endif
#endif

#ifdef TRACY_HAS_CALLSTACK

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

#ifdef _WIN32

void InitCallstack();
CallstackEntry DecodeCallstackPtr( uint64_t ptr );

static tracy_force_inline void* Callstack()
{
    enum { StackDepth = 24 };
    static_assert( StackDepth <= 63, "Stack depth can't be greater than 63." );

    auto trace = (uintptr_t*)tracy_malloc( ( 1 + StackDepth ) * sizeof( uintptr_t ) );
    const auto num = RtlCaptureStackBackTrace( 0, StackDepth, (void**)( trace+1 ), nullptr );
    *trace = num;

    return trace;
}

#endif

}

#endif

#endif
