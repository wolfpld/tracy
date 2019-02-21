//
//          Tracy profiler
//         ----------------
//
// For fast integration, compile and
// link with this source file (and none
// other) in your executable (or in the
// main DLL / shared object on multi-DLL
// projects).
//

// Define TRACY_ENABLE to enable profiler.

#include "common/TracySystem.cpp"

#ifdef TRACY_ENABLE

#include "common/tracy_lz4.cpp"
#include "client/TracyProfiler.cpp"
#include "client/TracyCallstack.cpp"
#include "client/TracySysTime.cpp"
#include "common/TracySocket.cpp"
#include "client/tracy_rpmalloc.cpp"

#ifdef __linux
#  include "libbacktrace/alloc.cpp"
#  include "libbacktrace/dwarf.cpp"
#  include "libbacktrace/elf.cpp"
#  include "libbacktrace/fileline.cpp"
#  include "libbacktrace/mmapio.cpp"
#  include "libbacktrace/posix.cpp"
#  include "libbacktrace/sort.cpp"
#  include "libbacktrace/state.cpp"
#endif

#ifdef _MSC_VER
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "dbghelp.lib")
#endif

#endif
