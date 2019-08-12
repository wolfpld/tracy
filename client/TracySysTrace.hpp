#ifndef __TRACYSYSTRACE_HPP__
#define __TRACYSYSTRACE_HPP__

#if defined _WIN32 || defined __CYGWIN__
#  define TRACY_HAS_SYSTEM_TRACING
#endif

#ifdef TRACY_HAS_SYSTEM_TRACING

namespace tracy
{

bool SysTraceStart();
void SysTraceStop();
void SysTraceWorker( void* ptr );

}

#endif

#endif
