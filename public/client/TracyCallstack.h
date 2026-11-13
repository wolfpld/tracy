#ifndef __TRACYCALLSTACK_H__
#define __TRACYCALLSTACK_H__

// Callstack address contract
// --------------------------
// Every address stored in a callstack lies inside the instruction that is executing in that frame (its "lookup address"):
//  - a frame that was interrupted (the leaf of a sample, a signal frame) stores the exact instruction pointer;
//  - every other frame is suspended in a call: it stores the return address minus 1, which lies inside the call instruction.
// The code that captures the stack (the walker) is the only one that knows which case applies, so it normalizes the
// addresses before they are queued. Symbolizers then look an address up as is, without compensation and without knowing
// how the stack was captured. See CallstackLookupAddress() in TracyCallstack.hpp.
#ifndef TRACY_NO_CALLSTACK

#  if defined _WIN32
#    include "../common/TracyWinFamily.hpp"
#    if !defined TRACY_WIN32_NO_DESKTOP
#      define TRACY_HAS_CALLSTACK 1
#    endif
#  elif defined __ANDROID__
#    if !defined __arm__ || __ANDROID_API__ >= 21
#      define TRACY_HAS_CALLSTACK 2
#    else
#      define TRACY_HAS_CALLSTACK 5
#    endif
#  elif defined __linux
#    if defined _GNU_SOURCE && defined __GLIBC__ && !defined TRACY_FORCE_UNWIND_BACKTRACE   // the define is a test knob
#      define TRACY_HAS_CALLSTACK 3
#    else
#      define TRACY_HAS_CALLSTACK 2
#    endif
#  elif defined __APPLE__
#    define TRACY_HAS_CALLSTACK 4
#  elif defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__ || defined __DragonFly__
#    define TRACY_HAS_CALLSTACK 6
#  endif

#if TRACY_HAS_CALLSTACK == 2 || TRACY_HAS_CALLSTACK == 3 || TRACY_HAS_CALLSTACK == 4 || TRACY_HAS_CALLSTACK == 6
#define TRACY_USE_LIBBACKTRACE
#endif

#endif

#endif
