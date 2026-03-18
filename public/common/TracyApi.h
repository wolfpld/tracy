#ifndef __TRACYAPI_H__
#define __TRACYAPI_H__

#if defined _WIN32
#  if defined TRACY_EXPORTS
#    if defined(__clang__)
#      define TRACY_API __declspec(dllexport) __attribute__((visibility("default")))
#    else
#      define TRACY_API __declspec(dllexport)
#    endif
#  elif defined TRACY_IMPORTS
#    if defined(__clang__)
#      define TRACY_API __declspec(dllimport) __attribute__((visibility("default")))
#    else
#      define TRACY_API __declspec(dllimport)
#    endif
#  else
#    if defined(__clang__)
#      define TRACY_API __attribute__((visibility("default")))
#    else
#      define TRACY_API
#    endif
#  endif
#else
#  define TRACY_API __attribute__((visibility("default")))
#endif

#endif    // __TRACYAPI_H__
