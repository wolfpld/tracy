#include <stdio.h>
#include "TracyCallstack.hpp"

#ifdef TRACY_HAS_CALLSTACK

#if TRACY_HAS_CALLSTACK == 1
#  include <windows.h>
#  ifdef _MSC_VER
#    pragma warning( push )
#    pragma warning( disable : 4091 )
#  endif
#  include <dbghelp.h>
#  ifdef _MSC_VER
#    pragma warning( pop )
#  endif
#elif TRACY_HAS_CALLSTACK >= 2
#  include "../libbacktrace/backtrace.hpp"
#  include <dlfcn.h>
#  include <cxxabi.h>
#endif

namespace tracy
{

#if TRACY_HAS_CALLSTACK == 1

extern "C" { t_RtlWalkFrameChain RtlWalkFrameChain = 0; }

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

CallstackEntryData DecodeCallstackPtr( uint64_t ptr )
{
    static CallstackEntry ret;

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

    return { &ret, 1 };
}

#elif TRACY_HAS_CALLSTACK >= 2

enum { MaxCbTrace = 1 };

struct backtrace_state* cb_bts;
int cb_num;
CallstackEntry cb_data[MaxCbTrace];

void InitCallstack()
{
    cb_bts = backtrace_create_state( nullptr, 0, nullptr, nullptr );
}

static inline char* CopyString( const char* src )
{
    const auto sz = strlen( src );
    auto dst = (char*)tracy_malloc( sz + 1 );
    memcpy( dst, src, sz );
    dst[sz] = '\0';
    return dst;
}

static int CallstackDataCb( void* data, uintptr_t pc, const char* fn, int lineno, const char* function )
{
    enum { DemangleBufLen = 64*1024 };
    char demangled[DemangleBufLen];

    if( !fn && !function )
    {
        const char* symname = nullptr;
        const char* symloc = nullptr;
        auto vptr = (void*)pc;
        ptrdiff_t symoff = 0;

        Dl_info dlinfo;
        if( dladdr( vptr, &dlinfo ) )
        {
            symloc = dlinfo.dli_fname;
            symname = dlinfo.dli_sname;
            symoff = (char*)pc - (char*)dlinfo.dli_saddr;

            if( symname && symname[0] == '_' )
            {
                size_t len = DemangleBufLen;
                int status;
                abi::__cxa_demangle( symname, demangled, &len, &status );
                if( status == 0 )
                {
                    symname = demangled;
                }
            }
        }

        if( !symname ) symname = "[unknown]";
        if( !symloc ) symloc = "[unknown]";

        if( symoff == 0 )
        {
            cb_data[cb_num].name = CopyString( symname );
        }
        else
        {
            char buf[32];
            const auto offlen = sprintf( buf, " + %td", symoff );
            const auto namelen = strlen( symname );
            auto name = (char*)tracy_malloc( namelen + offlen + 1 );
            memcpy( name, symname, namelen );
            memcpy( name + namelen, buf, offlen );
            name[namelen + offlen] = '\0';
            cb_data[cb_num].name = name;
        }

        char buf[32];
        const auto addrlen = sprintf( buf, " [%p]", (void*)pc );
        const auto loclen = strlen( symloc );
        auto loc = (char*)tracy_malloc( loclen + addrlen + 1 );
        memcpy( loc, symloc, loclen );
        memcpy( loc + loclen, buf, addrlen );
        loc[loclen + addrlen] = '\0';
        cb_data[cb_num].file = loc;

        cb_data[cb_num].line = 0;
    }
    else
    {
        if( !fn ) fn = "[unknown]";
        if( !function )
        {
            function = "[unknown]";
        }
        else
        {
            if( function[0] == '_' )
            {
                size_t len = DemangleBufLen;
                int status;
                abi::__cxa_demangle( function, demangled, &len, &status );
                if( status == 0 )
                {
                    function = demangled;
                }
            }
        }

        cb_data[cb_num].name = CopyString( function );
        cb_data[cb_num].file = CopyString( fn );
        cb_data[cb_num].line = lineno;
    }

    if( ++cb_num >= MaxCbTrace )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

static void CallstackErrorCb( void* data, const char* msg, int errnum )
{
    for( int i=0; i<cb_num; i++ )
    {
        tracy_free( (void*)cb_data[i].name );
        tracy_free( (void*)cb_data[i].file );
    }

    cb_data[0].name = CopyString( "[error]" );
    cb_data[0].file = CopyString( "[error]" );
    cb_data[0].line = 0;

    cb_num = 1;
}

CallstackEntryData DecodeCallstackPtr( uint64_t ptr )
{
    cb_num = 0;
    backtrace_pcinfo( cb_bts, ptr, CallstackDataCb, CallstackErrorCb, nullptr );
    assert( cb_num == 1 );
    return { cb_data, cb_num };
}

#endif

}

#endif
