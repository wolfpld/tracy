#ifndef __TRACYSORT_HPP__
#define __TRACYSORT_HPP__

#ifdef __EMSCRIPTEN__
#  include "tracy_pdqsort.h"
#else
#  include <ppqsort.h>
#endif

#endif
