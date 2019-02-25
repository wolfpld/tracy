#include "TracySysTime.hpp"

#ifdef TRACY_HAS_SYSTIME

#  if defined _WIN32 || defined __CYGWIN__
#    include <windows.h>
#  elif defined __linux__
#    include <assert.h>
#    include <stdio.h>
#    include <inttypes.h>
#  elif defined __APPLE__
#    include <mach/mach_host.h>
#    include <mach/host_info.h>
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

#  elif defined __APPLE__

void SysTime::ReadTimes()
{
    host_cpu_load_info_data_t info;
    mach_msg_type_number_t cnt = HOST_CPU_LOAD_INFO_COUNT;
    host_statistics( mach_host_self(), HOST_CPU_LOAD_INFO, reinterpret_cast<host_info_t>( &info ), &cnt ); 
    used = info.cpu_ticks[CPU_STATE_USER] + info.cpu_ticks[CPU_STATE_NICE] + info.cpu_ticks[CPU_STATE_SYSTEM];
    idle = info.cpu_ticks[CPU_STATE_IDLE];
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
    return diffUsed == 0 ? -1 : ( diffUsed - diffIdle ) * 100.f / diffUsed;
#elif defined __linux__ || defined __APPLE__
    const auto total = diffUsed + diffIdle;
    return total == 0 ? -1 : diffUsed * 100.f / total;
#endif
}

}

#endif
