#ifndef __TRACYSORT_HPP__
#define __TRACYSORT_HPP__

#ifndef NO_PARALLEL_SORT
#  if !defined __APPLE__ && ( ( defined _MSC_VER && _MSVC_LANG >= 201703L ) || __cplusplus >= 201703L )
#    if __has_include(<execution>)
#      include <algorithm>
#      include <execution>
#    else
#      define NO_PARALLEL_SORT
#    endif
#  else
#    define NO_PARALLEL_SORT
#  endif
#endif

#include "tracy_pdqsort.h"

#endif
