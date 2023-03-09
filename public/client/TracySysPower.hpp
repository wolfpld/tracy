#ifndef __TRACYSYSPOWER_HPP__
#define __TRACYSYSPOWER_HPP__

#if defined __linux__
#  define TRACY_HAS_SYSPOWER
#endif

#ifdef TRACY_HAS_SYSPOWER

namespace tracy
{

class SysPower
{
public:
    SysPower();
    ~SysPower();

    void Tick();
};

}
#endif

#endif
