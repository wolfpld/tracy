#include "TracyCallstack.hpp"

#ifdef TRACY_HAS_CALLSTACK

#if defined _WIN32 || defined __CYGWIN__
#  include <windows.h>
#  include <dbghelp.h>
#endif

namespace tracy
{

void InitCallstack()
{
    SymInitialize( GetCurrentProcess(), nullptr, true );
    SymSetOptions( SYMOPT_LOAD_LINES );
}

CallstackEntry DecodeCallstackPtr( uint64_t ptr )
{
    CallstackEntry ret;

    const auto proc = GetCurrentProcess();

    char buf[sizeof( SYMBOL_INFO ) + 255];
    auto si = (SYMBOL_INFO*)buf;
    si->SizeOfStruct = sizeof( SYMBOL_INFO );
    si->MaxNameLen = 255;

    if( SymFromAddr( proc, ptr, nullptr, si ) == 0 )
    {
        memcpy( si->Name, "[unknown]", 10 );
        si->NameLen = 9;
    }

    auto name = (char*)tracy_malloc( si->NameLen + 1 );
    memcpy( name, si->Name, si->NameLen );
    name[si->NameLen] = '\0';

    ret.name = name;

    const char* filename;
    IMAGEHLP_LINE64 line;
    DWORD displacement = 0;
    line.SizeOfStruct = sizeof( IMAGEHLP_LINE64 );
    if( SymGetLineFromAddr64( proc, ptr, &displacement, &line ) == 0 )
    {
        filename = "[unknown]";
        ret.line = 0;
    }
    else
    {
        filename = line.FileName;
        ret.line = line.LineNumber;
    }

    const auto fsz = strlen( filename );
    auto file = (char*)tracy_malloc( fsz + 1 );
    memcpy( file, filename, fsz );
    file[fsz] = '\0';

    ret.file = file;

    return ret;
}

}

#endif
