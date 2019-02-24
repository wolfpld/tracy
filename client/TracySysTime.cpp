#include "TracySysTime.hpp"

#ifdef TRACY_HAS_SYSTIME

#  if defined _WIN32 || defined __CYGWIN__
#    include <windows.h>
#  elif defined __linux__
#    include <assert.h>
#    include <stdio.h>
#    include <inttypes.h>
#  endif

namespace tracy
{

#  if defined _WIN32 || defined __CYGWIN__

static inline uint64_t ConvertTime( const FILETIME& t )
{
    return ( uint64_t( t.dwHighDateTime ) << 32 ) | uint64_t( t.dwLowDateTime );
}

void SysTime::ReadTimes()
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

#  elif defined __linux__

void SysTime::ReadTimes()
{
    uint64_t user, nice, system;
    FILE* f = fopen( "/proc/stat", "r" );
    assert( f );
    fscanf( f, "cpu %" PRIu64 " %" PRIu64 " %" PRIu64" %" PRIu64, &user, &nice, &system, &idle );
    fclose( f );
    used = user + nice + system;
}

#endif

SysTime::SysTime()
{
    ReadTimes();
}

float SysTime::Get()
{
    const auto oldUsed = used;
    const auto oldIdle = idle;

    ReadTimes();

    const auto diffIdle = idle - oldIdle;
    const auto diffUsed = used - oldUsed;

#if defined _WIN32 || defined __CYGWIN__
    return diffUsed == 0 ? 0 : ( diffUsed - diffIdle ) * 100.f / diffUsed;
#elif defined __linux__
    const auto total = diffUsed + diffIdle;
    return total == 0 ? 0 : diffUsed * 100.f / total;
#endif
}

}

#endif
