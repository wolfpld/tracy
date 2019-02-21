#include "TracySysTime.hpp"

#ifdef TRACY_HAS_SYSTIME

#  if defined _WIN32 || defined __CYGWIN__
#    include <windows.h>
#  endif

namespace tracy
{

#  if defined _WIN32 || defined __CYGWIN__

static inline uint64_t ConvertTime( const FILETIME& t )
{
    return ( uint64_t( t.dwHighDateTime ) << 32 ) | uint64_t( t.dwLowDateTime );
}

SysTime::SysTime()
{
    FILETIME idleTime;
    FILETIME kernelTime;
    FILETIME userTime;

    GetSystemTimes( &idleTime, &kernelTime, &userTime );

    idle = ConvertTime( idleTime );
    const auto kernel = ConvertTime( kernelTime );
    const auto user = ConvertTime( userTime );
    used = kernel + user;
}

float SysTime::Get()
{
    FILETIME idleTime;
    FILETIME kernelTime;
    FILETIME userTime;

    GetSystemTimes( &idleTime, &kernelTime, &userTime );

    const auto newIdle = ConvertTime( idleTime );
    const auto kernel = ConvertTime( kernelTime );
    const auto user = ConvertTime( userTime );
    const auto newUsed = kernel + user;

    const auto diffIdle = newIdle - idle;
    const auto diffUsed = newUsed - used;

    idle = newIdle;
    used = newUsed;

    return diffUsed == 0 ? 0 : ( diffUsed - diffIdle ) * 100.f / diffUsed;
}

#  endif

}

#endif
