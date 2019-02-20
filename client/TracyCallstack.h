#ifndef __TRACYCALLSTACK_H__
#define __TRACYCALLSTACK_H__

#if defined _WIN32 || defined __CYGWIN__
#  define TRACY_HAS_CALLSTACK 1
#elif defined __ANDROID__
#  define TRACY_HAS_CALLSTACK 2
#elif defined __linux
#  if defined _GNU_SOURCE && defined __GLIBC__
#    define TRACY_HAS_CALLSTACK 3
#  else
#    define TRACY_HAS_CALLSTACK 2
#  endif
#elif defined __APPLE__
#  define TRACY_HAS_CALLSTACK 4
#endif

#endif
