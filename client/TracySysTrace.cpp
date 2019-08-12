#include "TracySysTrace.hpp"

#ifdef TRACY_HAS_SYSTEM_TRACING

namespace tracy
{

bool SysTraceStart()
{
    return true;
}

void SysTraceStop()
{
}

void SysTraceWorker( void* ptr )
{
}

}

#endif
