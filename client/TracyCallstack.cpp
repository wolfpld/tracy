#include <stdio.h>
#include "TracyCallstack.hpp"

#ifdef TRACY_HAS_CALLSTACK

#if defined _WIN32 || defined __CYGWIN__
#  include <windows.h>
#  include <dbghelp.h>
#elif defined _GNU_SOURCE
#  include <dlfcn.h>
#  include <cxxabi.h>
#endif

namespace tracy
{

#if defined _WIN32 || defined __CYGWIN__

extern "C" t_RtlWalkFrameChain RtlWalkFrameChain = 0;

void InitCallstack()
{
#ifdef UNICODE
    RtlWalkFrameChain = (t_RtlWalkFrameChain)GetProcAddress( GetModuleHandle( L"ntdll.dll" ), "RtlWalkFrameChain" );
#else
    RtlWalkFrameChain = (t_RtlWalkFrameChain)GetProcAddress( GetModuleHandle( "ntdll.dll" ), "RtlWalkFrameChain" );
#endif
    SymInitialize( GetCurrentProcess(), nullptr, true );
    SymSetOptions( SYMOPT_LOAD_LINES );
}

CallstackEntry DecodeCallstackPtr( uint64_t ptr )
{
    CallstackEntry ret;

    const auto proc = GetCurrentProcess();

    char buf[sizeof( SYMBOL_INFO ) + 1024];
    auto si = (SYMBOL_INFO*)buf;
    si->SizeOfStruct = sizeof( SYMBOL_INFO );
    si->MaxNameLen = 1024;

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

#elif defined __ANDROID__

CallstackEntry DecodeCallstackPtr( uint64_t ptr )
{
    CallstackEntry ret;
    ret.line = 0;

    char* demangled = nullptr;
    const char* symname = nullptr;
    const char* symloc = nullptr;
    auto vptr = (void*)ptr;
    char** sym = nullptr;
    ptrdiff_t symoff = 0;

    Dl_info dlinfo;
    if( dladdr( vptr, &dlinfo ) )
    {
        symloc = dlinfo.dli_fname;
        symname = dlinfo.dli_sname;
        symoff = (char*)ptr - (char*)dlinfo.dli_saddr;

        if( symname && symname[0] == '_' )
        {
            size_t len = 0;
            int status;
            demangled = abi::__cxa_demangle( symname, nullptr, &len, &status );
            if( status == 0 )
            {
                symname = demangled;
            }
        }
    }

    if( !symname )
    {
        symname = "[unknown]";
    }
    if( !symloc )
    {
        symloc = "[unknown]";
    }

    if( symoff == 0 )
    {
        const auto namelen = strlen( symname );
        auto name = (char*)tracy_malloc( namelen + 1 );
        memcpy( name, symname, namelen );
        name[namelen] = '\0';
        ret.name = name;
    }
    else
    {
        char buf[32];
        sprintf( buf, " + %td", symoff );
        const auto offlen = strlen( buf );
        const auto namelen = strlen( symname );
        auto name = (char*)tracy_malloc( namelen + offlen + 1 );
        memcpy( name, symname, namelen );
        memcpy( name + namelen, buf, offlen );
        name[namelen + offlen] = '\0';
        ret.name = name;
    }

    char buf[32];
    sprintf( buf, " [%p]", (void*)ptr );
    const auto addrlen = strlen( buf );
    const auto loclen = strlen( symloc );
    auto loc = (char*)tracy_malloc( loclen + addrlen + 1 );
    memcpy( loc, symloc, loclen );
    memcpy( loc + loclen, buf, addrlen );
    loc[loclen + addrlen] = '\0';
    ret.file = loc;

    if( sym ) free( sym );
    if( demangled ) free( demangled );

    return ret;
}

#elif defined _GNU_SOURCE

CallstackEntry DecodeCallstackPtr( uint64_t ptr )
{
    CallstackEntry ret;
    ret.line = 0;

    char* demangled = nullptr;
    const char* symname = nullptr;
    const char* symloc = nullptr;
    auto vptr = (void*)ptr;
    char** sym = nullptr;
    ptrdiff_t symoff = 0;

    Dl_info dlinfo;
    if( dladdr( vptr, &dlinfo ) )
    {
        symloc = dlinfo.dli_fname;
        symname = dlinfo.dli_sname;
        symoff = (char*)ptr - (char*)dlinfo.dli_saddr;

        if( symname && symname[0] == '_' )
        {
            size_t len = 0;
            int status;
            demangled = abi::__cxa_demangle( symname, nullptr, &len, &status );
            if( status == 0 )
            {
                symname = demangled;
            }
        }
    }

    if( !symname )
    {
        sym = backtrace_symbols( &vptr, 1 );
        if( !sym )
        {
            symname = "[unknown]";
        }
        else
        {
            symname = *sym;
        }
    }
    if( !symloc )
    {
        symloc = "[unknown]";
    }

    if( symoff == 0 )
    {
        const auto namelen = strlen( symname );
        auto name = (char*)tracy_malloc( namelen + 1 );
        memcpy( name, symname, namelen );
        name[namelen] = '\0';
        ret.name = name;
    }
    else
    {
        char buf[32];
        sprintf( buf, " + %td", symoff );
        const auto offlen = strlen( buf );
        const auto namelen = strlen( symname );
        auto name = (char*)tracy_malloc( namelen + offlen + 1 );
        memcpy( name, symname, namelen );
        memcpy( name + namelen, buf, offlen );
        name[namelen + offlen] = '\0';
        ret.name = name;
    }

    char buf[32];
    sprintf( buf, " [%p]", (void*)ptr );
    const auto addrlen = strlen( buf );
    const auto loclen = strlen( symloc );
    auto loc = (char*)tracy_malloc( loclen + addrlen + 1 );
    memcpy( loc, symloc, loclen );
    memcpy( loc + loclen, buf, addrlen );
    loc[loclen + addrlen] = '\0';
    ret.file = loc;

    if( sym ) free( sym );
    if( demangled ) free( demangled );

    return ret;
}

#endif

}

#endif
