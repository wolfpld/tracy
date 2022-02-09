#ifndef __TRACYSYSTRACE_HPP__
#define __TRACYSYSTRACE_HPP__

#if !defined TRACY_NO_SYSTEM_TRACING && ( defined _WIN32 || defined __linux__ )
#  if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP) && \
      !WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#  else
#    define TRACY_HAS_SYSTEM_TRACING
#  endif
#endif

#ifdef TRACY_HAS_SYSTEM_TRACING

#include <stdint.h>

namespace tracy
{

bool SysTraceStart( int64_t& samplingPeriod );
void SysTraceStop();
void SysTraceWorker( void* ptr );

void SysTraceGetExternalName( uint64_t thread, const char*& threadName, const char*& name );

}

#endif

#endif
