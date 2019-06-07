#ifndef __TRACYAPI_H__
#define __TRACYAPI_H__

#ifdef _WIN32
#  if defined TRACY_IMPORTS
#    define TRACY_API __declspec(dllimport)
#  else
#    define TRACY_API __declspec(dllexport)
#  endif
#else
#  define TRACY_API __attribute__((visibility("default")))
#endif

#endif    // __TRACYAPI_H__
