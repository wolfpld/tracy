#ifndef __TRACYFORCEINLINE_HPP__
#define __TRACYFORCEINLINE_HPP__

#if defined(__GNUC__)
#  define tracy_force_inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#  define tracy_force_inline __forceinline
#else
#  define tracy_force_inline inline
#endif

#endif
