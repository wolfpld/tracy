//
//          Tracy profiler
//         ----------------
//
// For fast integration, compile and
// link with this source file (and none
// other).
//

#include "client/tracy_rpmalloc.cpp"
#include "client/TracyProfiler.cpp"
#include "common/tracy_lz4.cpp"
#include "common/TracySocket.cpp"
#include "common/TracySystem.cpp"

#ifdef _MSC_VER
#  pragma comment(lib, "ws2_32.lib")
#endif
