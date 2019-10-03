//
//          Tracy profiler
//         ----------------
//
// On multi-DLL projects compile and
// link with this source file (and none
// other) in the executable and in
// DLLs / shared objects that link to
// the main DLL.
//

// Define TRACY_ENABLE to enable profiler.

#ifdef TRACY_ENABLE
#  ifndef TRACY_IMPORTS
#    define TRACY_IMPORTS 1
#  endif
#endif
#include "common/TracySystem.cpp"
