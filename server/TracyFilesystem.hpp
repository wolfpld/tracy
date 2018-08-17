#ifndef __TRACYFILESYSTEM_HPP__
#define __TRACYFILESYSTEM_HPP__

#include <sys/stat.h>

namespace tracy
{

static inline bool FileExists( const char* fn )
{
    struct stat buf;
    return stat( fn, &buf ) == 0 && ( buf.st_mode & S_IFREG ) != 0;
}

}

#endif
