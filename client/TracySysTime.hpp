#ifndef __TRACYSYSTIME_HPP__
#define __TRACYSYSTIME_HPP__

#ifdef _WIN32
#  define TRACY_HAS_SYSTIME
#endif

#ifdef TRACY_HAS_SYSTIME

#include <stdint.h>

namespace tracy
{

class SysTime
{
public:
    SysTime();
    float Get();

private:
#  ifdef _WIN32
    uint64_t idle, used;
#  endif
};

}
#endif

#endif
