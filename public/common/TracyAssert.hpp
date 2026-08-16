#ifndef __TRACYASSERT_HPP__
#define __TRACYASSERT_HPP__

// Define TRACY_ASSERT(condition) before including any Tracy header to
// route the internal checks through a custom assert implementation.
// Falls back to the standard assert when not defined.
#ifndef TRACY_ASSERT
#  include <assert.h>
#  define TRACY_ASSERT(x) assert(x)
#endif

#endif
