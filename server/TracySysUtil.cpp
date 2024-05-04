

#include "TracySysUtil.hpp"

#ifdef _WIN32
#  include <windows.h>
#elif defined __linux__
#  include <sys/sysinfo.h>
#elif defined __APPLE__ || defined BSD
#  include <sys/types.h>
#  include <sys/sysctl.h>
#endif

namespace tracy
{

size_t GetPhysicalMemorySize()
{
#ifdef _WIN32
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof( statex );
    GlobalMemoryStatusEx( &statex );
    return statex.ullTotalPhys;
#elif defined __linux__
    struct sysinfo sysInfo;
    sysinfo( &sysInfo );
    return sysInfo.totalram;
#elif defined __APPLE__
    size_t memSize;
    size_t sz = sizeof( memSize );
    sysctlbyname( "hw.memsize", &memSize, &sz, nullptr, 0 );
    return memSize;
#elif defined BSD
    size_t memSize;
    size_t sz = sizeof( memSize );
    sysctlbyname( "hw.physmem", &memSize, &sz, nullptr, 0 );
    return memSize;
#else
    return 0;
#endif
}

}
