#include <stdio.h>
#include <string.h>
#include "TracyCallstack.hpp"

#ifdef TRACY_HAS_CALLSTACK

#if TRACY_HAS_CALLSTACK == 1
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  ifdef _MSC_VER
#    pragma warning( push )
#    pragma warning( disable : 4091 )
#  endif
#  include <dbghelp.h>
#  ifdef _MSC_VER
#    pragma warning( pop )
#  endif
#elif TRACY_HAS_CALLSTACK == 2 || TRACY_HAS_CALLSTACK == 3 || TRACY_HAS_CALLSTACK == 4 || TRACY_HAS_CALLSTACK == 6
#  include "../libbacktrace/backtrace.hpp"
#  include <dlfcn.h>
#  include <cxxabi.h>
#elif TRACY_HAS_CALLSTACK == 5
#  include <dlfcn.h>
#  include <cxxabi.h>
#endif

namespace tracy
{

#if TRACY_HAS_CALLSTACK == 1

enum { MaxCbTrace = 16 };

int cb_num;
CallstackEntry cb_data[MaxCbTrace];

extern "C"
{
    typedef unsigned long (__stdcall *t_RtlWalkFrameChain)( void**, unsigned long, unsigned long );
    t_RtlWalkFrameChain RtlWalkFrameChain = 0;
}

#if defined __MINGW32__ && API_VERSION_NUMBER < 12
extern "C" {
// Actual required API_VERSION_NUMBER is unknown because it is undocumented. These functions are not present in at least v11.
DWORD IMAGEAPI SymAddrIncludeInlineTrace(HANDLE hProcess, DWORD64 Address);
BOOL IMAGEAPI SymQueryInlineTrace(HANDLE hProcess, DWORD64 StartAddress, DWORD StartContext, DWORD64 StartRetAddress,
    DWORD64 CurAddress, LPDWORD CurContext, LPDWORD CurFrameIndex);
BOOL IMAGEAPI SymFromInlineContext(HANDLE hProcess, DWORD64 Address, ULONG InlineContext, PDWORD64 Displacement,
    PSYMBOL_INFO Symbol);
BOOL IMAGEAPI SymGetLineFromInlineContext(HANDLE hProcess, DWORD64 qwAddr, ULONG InlineContext,
    DWORD64 qwModuleBaseAddress, PDWORD pdwDisplacement, PIMAGEHLP_LINE64 Line64);
};
#endif

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

TRACY_API tracy_force_inline uintptr_t* CallTrace( int depth )
{
    auto trace = (uintptr_t*)tracy_malloc( ( 1 + depth ) * sizeof( uintptr_t ) );
    const auto num = RtlWalkFrameChain( (void**)( trace + 1 ), depth, 0 );
    *trace = num;
    return trace;
}

const char* DecodeCallstackPtrFast( uint64_t ptr )
{
    static char ret[1024];
    const auto proc = GetCurrentProcess();

    char buf[sizeof( SYMBOL_INFO ) + 1024];
    auto si = (SYMBOL_INFO*)buf;
    si->SizeOfStruct = sizeof( SYMBOL_INFO );
    si->MaxNameLen = 1024;

    if( SymFromAddr( proc, ptr, nullptr, si ) == 0 )
    {
        *ret = '\0';
    }
    else
    {
        memcpy( ret, si->Name, si->NameLen );
        ret[si->NameLen] = '\0';
    }
    return ret;
}

CallstackEntryData DecodeCallstackPtr( uint64_t ptr )
{
    int write;
    const auto proc = GetCurrentProcess();
#ifndef __CYGWIN__
    DWORD inlineNum = SymAddrIncludeInlineTrace( proc, ptr );
    if( inlineNum > MaxCbTrace - 1 ) inlineNum = MaxCbTrace - 1;
    DWORD ctx = 0;
    DWORD idx;
    BOOL doInline = FALSE;
    if( inlineNum != 0 ) doInline = SymQueryInlineTrace( proc, ptr, 0, ptr, ptr, &ctx, &idx );
    if( doInline )
    {
        write = inlineNum;
        cb_num = 1 + inlineNum;
    }
    else
#endif
    {
        write = 0;
        cb_num = 1;
    }

    char buf[sizeof( SYMBOL_INFO ) + 1024];
    auto si = (SYMBOL_INFO*)buf;
    si->SizeOfStruct = sizeof( SYMBOL_INFO );
    si->MaxNameLen = 1024;

    if( SymFromAddr( proc, ptr, nullptr, si ) == 0 )
    {
        memcpy( si->Name, "[unknown]", 10 );
        si->NameLen = 9;
    }

    IMAGEHLP_LINE64 line;
    DWORD displacement = 0;
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

    {
        auto name = (char*)tracy_malloc(si->NameLen + 1);
        memcpy(name, si->Name, si->NameLen);
        name[si->NameLen] = '\0';

        cb_data[write].name = name;

        const char* filename;
        if (SymGetLineFromAddr64(proc, ptr, &displacement, &line) == 0)
        {
            filename = "[unknown]";
            cb_data[write].line = 0;
        }
        else
        {
            filename = line.FileName;
            cb_data[write].line = line.LineNumber;
        }

        const auto fsz = strlen(filename);
        auto file = (char*)tracy_malloc(fsz + 1);
        memcpy(file, filename, fsz);
        file[fsz] = '\0';

        cb_data[write].file = file;
    }

#ifndef __CYGWIN__
    if( doInline )
    {
        for( DWORD i=0; i<inlineNum; i++ )
        {
            auto& cb = cb_data[i];

            if( SymFromInlineContext( proc, ptr, ctx, nullptr, si ) == 0 )
            {
                memcpy( si->Name, "[unknown]", 10 );
                si->NameLen = 9;
            }

            auto name = (char*)tracy_malloc( si->NameLen + 1 );
            memcpy( name, si->Name, si->NameLen );
            name[si->NameLen] = '\0';
            cb.name = name;

            const char* filename;
            if( SymGetLineFromInlineContext( proc, ptr, ctx, 0, &displacement, &line ) == 0 )
            {
                filename = "[unknown]";
                cb.line = 0;
            }
            else
            {
                filename = line.FileName;
                cb.line = line.LineNumber;
            }

            const auto fsz = strlen( filename );
            auto file = (char*)tracy_malloc( fsz + 1 );
            memcpy( file, filename, fsz );
            file[fsz] = '\0';
            cb.file = file;

            ctx++;
        }
    }
#endif

    return { cb_data, uint8_t( cb_num ) };
}

#elif TRACY_HAS_CALLSTACK == 2 || TRACY_HAS_CALLSTACK == 3 || TRACY_HAS_CALLSTACK == 4 || TRACY_HAS_CALLSTACK == 6

enum { MaxCbTrace = 16 };

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

static int FastCallstackDataCb( void* data, uintptr_t pc, const char* fn, int lineno, const char* function )
{
    if( function )
    {
        strcpy( (char*)data, function );
    }
    else
    {
        const char* symname = nullptr;
        auto vptr = (void*)pc;
        Dl_info dlinfo;
        if( dladdr( vptr, &dlinfo ) )
        {
            symname = dlinfo.dli_sname;
        }
        if( symname )
        {
            strcpy( (char*)data, symname );
        }
        else
        {
            *(char*)data = '\0';
        }
    }
    return 1;
}

static void FastCallstackErrorCb( void* data, const char* /*msg*/, int /*errnum*/ )
{
    *(char*)data = '\0';
}

const char* DecodeCallstackPtrFast( uint64_t ptr )
{
    static char ret[1024];
    backtrace_pcinfo( cb_bts, ptr, FastCallstackDataCb, FastCallstackErrorCb, ret );
    return ret;
}

static int CallstackDataCb( void* /*data*/, uintptr_t pc, const char* fn, int lineno, const char* function )
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

static void CallstackErrorCb( void* /*data*/, const char* /*msg*/, int /*errnum*/ )
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
    assert( cb_num > 0 );
    return { cb_data, uint8_t( cb_num ) };
}

#elif TRACY_HAS_CALLSTACK == 5

void InitCallstack()
{
}

const char* DecodeCallstackPtrFast( uint64_t ptr )
{
    static char ret[1024];
    auto vptr = (void*)ptr;
    char** sym = nullptr;
    const char* symname = nullptr;
    Dl_info dlinfo;
    if( dladdr( vptr, &dlinfo ) && dlinfo.dli_sname )
    {
        symname = dlinfo.dli_sname;
    }
    if( symname )
    {
        strcpy( ret, symname );
    }
    else
    {
        *ret = '\0';
    }
    return ret;
}

CallstackEntryData DecodeCallstackPtr( uint64_t ptr )
{
    static CallstackEntry cb;
    cb.line = 0;

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
        cb.name = name;
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
        cb.name = name;
    }

    char buf[32];
    const auto addrlen = sprintf( buf, " [%p]", (void*)ptr );
    const auto loclen = strlen( symloc );
    auto loc = (char*)tracy_malloc( loclen + addrlen + 1 );
    memcpy( loc, symloc, loclen );
    memcpy( loc + loclen, buf, addrlen );
    loc[loclen + addrlen] = '\0';
    cb.file = loc;

    if( sym ) free( sym );
    if( demangled ) free( demangled );

    return { &cb, 1 };
}

#endif

}

#endif
