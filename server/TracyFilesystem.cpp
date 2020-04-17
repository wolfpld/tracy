#include "TracyFilesystem.hpp"
#include "TracyView.hpp"

namespace tracy
{

bool SourceFileValid( const char* fn, uint64_t olderThan, const View& view )
{
    struct stat buf;
    if( stat( view.SourceSubstitution( fn ), &buf ) == 0 && ( buf.st_mode & S_IFREG ) != 0 )
    {
        return (uint64_t)buf.st_mtime < olderThan;
    }
    return false;
}

}
