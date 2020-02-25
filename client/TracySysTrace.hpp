#ifndef __TRACYSYSTRACE_HPP__
#define __TRACYSYSTRACE_HPP__

#if !defined TRACY_NO_SYSTEM_TRACING && ( defined _WIN32 || defined __CYGWIN__ || defined __linux__ )
#  define TRACY_HAS_SYSTEM_TRACING
#endif

#ifdef TRACY_HAS_SYSTEM_TRACING

#include <stdint.h>

namespace tracy
{

bool SysTraceStart( int64_t& samplingPeriod );
void SysTraceStop();
void SysTraceWorker( void* ptr );

void SysTraceSendExternalName( uint64_t thread );

}

#endif

#endif
