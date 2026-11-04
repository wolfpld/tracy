#include "TracySysTime.hpp"

#ifdef TRACY_HAS_SYSTIME

#  if defined _WIN32
#    include <windows.h>
#    include "../common/TracyWinFamily.hpp"
#  elif defined __linux__
#    include <stdio.h>
#    include <inttypes.h>
#  elif defined __APPLE__
#    include <mach/mach_host.h>
#    include <mach/host_info.h>
#  elif defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__ || defined __DragonFly__
#    include <sys/types.h>
#    include <sys/sysctl.h>
#  endif

namespace tracy
{

#  if defined _WIN32

static inline uint64_t ConvertTime( const FILETIME& t )
{
    return ( uint64_t( t.dwHighDateTime ) << 32 ) | uint64_t( t.dwLowDateTime );
}

bool SysTime::ReadTimes()
{
    FILETIME kernelTime;
    FILETIME userTime;

#    if defined TRACY_GDK
    FILETIME creationTime;
    FILETIME exitTime;

    if( !GetProcessTimes( GetCurrentProcess(), &creationTime, &exitTime, &kernelTime, &userTime ) ) return false;

    idle = 0;
#    else
    FILETIME idleTime;

    if( !GetSystemTimes( &idleTime, &kernelTime, &userTime ) ) return false;

    idle = ConvertTime( idleTime );
#    endif

    const auto kernel = ConvertTime( kernelTime );
    const auto user = ConvertTime( userTime );
    used = kernel + user;
    return true;
}

#  elif defined __linux__

bool SysTime::ReadTimes()
{
    uint64_t user, nice, system, idleTicks;
    FILE* f = fopen( "/proc/stat", "r" );
    if( !f ) return false;

    const int read = fscanf( f, "cpu %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64, &user, &nice, &system, &idleTicks );
    fclose( f );
    if( read != 4 ) return false;

    used = user + nice + system;
    idle = idleTicks;
    return true;
}

#  elif defined __APPLE__

bool SysTime::ReadTimes()
{
    host_cpu_load_info_data_t info;
    mach_msg_type_number_t cnt = HOST_CPU_LOAD_INFO_COUNT;
    if( host_statistics( mach_host_self(), HOST_CPU_LOAD_INFO, reinterpret_cast<host_info_t>( &info ), &cnt ) != KERN_SUCCESS ) return false;
    used = info.cpu_ticks[CPU_STATE_USER] + info.cpu_ticks[CPU_STATE_NICE] + info.cpu_ticks[CPU_STATE_SYSTEM];
    idle = info.cpu_ticks[CPU_STATE_IDLE];
    return true;
}

#  elif defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__ || defined __DragonFly__

bool SysTime::ReadTimes()
{
    u_long data[5];
    size_t sz = sizeof( data );
    if( sysctlbyname( "kern.cp_time", &data, &sz, nullptr, 0 ) != 0 ) return false;
    used = data[0] + data[1] + data[2] + data[3];
    idle = data[4];
    return true;
}

#endif

SysTime::SysTime()
    : idle( 0 )
    , used( 0 )
    , haveBaseline( false )
{
    haveBaseline = ReadTimes();
}

float SysTime::Get()
{
    const auto oldUsed = used;
    const auto oldIdle = idle;

    if( !ReadTimes() )
    {
        haveBaseline = false;
        return -1;
    }
    else if( !haveBaseline )
    {
        haveBaseline = true;
        return -1;
    }

    const auto diffIdle = idle - oldIdle;
    const auto diffUsed = used - oldUsed;

#if defined _WIN32
    return diffUsed == 0 ? -1 : ( diffUsed - diffIdle ) * 100.f / diffUsed;
#elif defined __linux__ || defined __APPLE__ || defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__ || defined __DragonFly__
    const auto total = diffUsed + diffIdle;
    return total == 0 ? -1 : diffUsed * 100.f / total;
#endif
}

}

#endif
