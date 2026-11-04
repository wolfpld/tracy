#ifndef __TRACYSYSTIME_HPP__
#define __TRACYSYSTIME_HPP__

#if defined _WIN32 || defined __linux__ || defined __APPLE__ || defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__ || defined __DragonFly__
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
    bool ReadTimes();

    uint64_t idle, used;
    bool haveBaseline;
};

}
#endif

#endif
