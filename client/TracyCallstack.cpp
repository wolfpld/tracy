#include "TracyCallstack.hpp"

#ifdef TRACY_HAS_CALLSTACK

#if defined _WIN32 || defined __CYGWIN__
#  ifndef MAXLONG
enum { SYMOPT_LOAD_LINES = 0x00000010 };
typedef struct _SYMBOL_INFO
{
    unsigned long SizeOfStruct;
    unsigned long TypeIndex;
    unsigned long long Reserved[2];
    unsigned long Index;
    unsigned long Size;
    unsigned long long ModBase;
    unsigned long Flags;
    unsigned long long Value;
    unsigned long long Address;
    unsigned long Register;
    unsigned long Scope;
    unsigned long Tag;
    unsigned long NameLen;
    unsigned long MaxNameLen;
    char Name[1];
} SYMBOL_INFO;
typedef struct _IMAGEHLP_LINE64
{
    unsigned long SizeOfStruct;
    void* Key;
    unsigned LineNumber;
    char* FileName;
    unsigned long long Address;
} IMAGEHLP_LINE64;
extern "C" __declspec(dllimport) void* __stdcall GetCurrentProcess();
extern "C" __declspec(dllimport) int __stdcall SymInitialize( void*, const char*, int );
extern "C" __declspec(dllimport) unsigned long __stdcall SymSetOptions( unsigned long );
extern "C" __declspec(dllimport) int __stdcall SymFromAddr( void*, unsigned long long, unsigned long long*, SYMBOL_INFO* );
extern "C" __declspec(dllimport) int __stdcall SymGetLineFromAddr64( void*, unsigned long long, unsigned long*, IMAGEHLP_LINE64* );
#  else
#    include <dbghelp.h>
#  endif
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

    SymFromAddr( proc, ptr, nullptr, si );

    auto name = (char*)tracy_malloc( si->NameLen + 1 );
    memcpy( name, si->Name, si->NameLen );
    name[si->NameLen] = '\0';

    ret.name = name;

    IMAGEHLP_LINE64 line;
    unsigned long displacement = 0;
    line.SizeOfStruct = sizeof( IMAGEHLP_LINE64 );
    SymGetLineFromAddr64( proc, ptr, &displacement, &line );

    ret.file = line.FileName;
    ret.line = line.LineNumber;

    return ret;
}

}

#endif
