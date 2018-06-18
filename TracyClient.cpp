//
//          Tracy profiler
//         ----------------
//
// For fast integration, compile and
// link with this source file (and none
// other).
//

// Define TRACY_ENABLE to enable profiler.

#include "common/TracySystem.cpp"

#ifdef TRACY_ENABLE

#include "client/TracyProfiler.cpp"
#include "client/TracyCallstack.cpp"
#include "common/tracy_lz4.cpp"
#include "common/TracySocket.cpp"
#include "client/tracy_rpmalloc.cpp"

#ifdef _MSC_VER
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "dbghelp.lib")
#endif

#endif
