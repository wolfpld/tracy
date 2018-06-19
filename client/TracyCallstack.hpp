#ifndef __TRACYCALLSTACK_HPP__
#define __TRACYCALLSTACK_HPP__

#if defined _WIN32 || defined __CYGWIN__
#  define TRACY_HAS_CALLSTACK
#  ifndef MAXLONG
#    ifdef __CYGWIN__
extern "C" __declspec(dllimport) unsigned short __stdcall RtlCaptureStackBackTrace( unsigned int, unsigned int, void**, unsigned int* );
#    else
extern "C" __declspec(dllimport) unsigned short __stdcall RtlCaptureStackBackTrace( unsigned long, unsigned long, void**, unsigned long* );
#    endif
#  endif
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

#if defined _WIN32 || defined __CYGWIN__

void InitCallstack();
CallstackEntry DecodeCallstackPtr( uint64_t ptr );

static tracy_force_inline void* Callstack( int depth )
{
    assert( depth >= 1 && depth <= 63 );

    auto trace = (uintptr_t*)tracy_malloc( ( 1 + depth ) * sizeof( uintptr_t ) );
    const auto num = RtlCaptureStackBackTrace( 0, depth, (void**)( trace+1 ), nullptr );
    *trace = num;

    return trace;
}

#endif

}

#endif

#endif
