#include "TracyFilesystem.hpp"
#include "TracyView.hpp"

namespace tracy
{

bool SourceFileValid( const char* fn, uint64_t olderThan, const View& view, const Worker& worker )
{
    if( worker.GetSourceFileFromCache( fn ).data != nullptr ) return true;
    struct stat buf;
    if( stat( view.SourceSubstitution( fn ), &buf ) == 0 && ( buf.st_mode & S_IFREG ) != 0 )
    {
        if(!view.ValidateSourceAge()) return true;
        return (uint64_t)buf.st_mtime < olderThan;
    }
    return false;
}

}
