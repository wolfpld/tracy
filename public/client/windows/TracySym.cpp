#include "../TracyCallstack.h"

// Windows host  --->  TRACY_HAS_CALLSTACK == 1
#if defined(TRACY_HAS_CALLSTACK) && (TRACY_HAS_CALLSTACK == 1)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>

#ifdef _MSC_VER
#pragma warning( push )
#pragma warning( disable : 4091 )
#endif
#include <dbghelp.h>
#pragma comment( lib, "dbghelp.lib" )
#ifdef _MSC_VER
#pragma warning( pop )
#endif

#include "../TracyProfiler.hpp"

#ifdef TRACY_DBGHELP_LOCK
#  define DBGHELP_INIT TracyConcat( TRACY_DBGHELP_LOCK, Init() )
#  define DBGHELP_LOCK TracyConcat( TRACY_DBGHELP_LOCK, Lock() );
#  define DBGHELP_UNLOCK TracyConcat( TRACY_DBGHELP_LOCK, Unlock() );

extern "C"
{
    void DBGHELP_INIT;
    void DBGHELP_LOCK;
    void DBGHELP_UNLOCK;
};
#else
#  define DBGHELP_INIT
#  define DBGHELP_LOCK
#  define DBGHELP_UNLOCK
#endif

#ifndef TRACY_SYMBOL_PATH
#define TRACY_SYMBOL_PATH ""
#endif

namespace tracy
{

struct DbgHelpScopedLock
{
    tracy_force_inline DbgHelpScopedLock() { DBGHELP_LOCK; }
    tracy_force_inline ~DbgHelpScopedLock() { DBGHELP_UNLOCK; }
};

#define DBGHELP_SCOPED_LOCK ::tracy::DbgHelpScopedLock dbgHelpLock;

#ifndef DBGHELP_DEBUG_LEVEL
#define DBGHELP_DEBUG_LEVEL (0)
#endif

static void TracySymError( const char* function, DWORD code )
{
    if( code == ERROR_SUCCESS ) return;
    constexpr uint32_t Color_Red4 = 0x8b0000;
    static constexpr tracy::SourceLocationData srcLocHere{ nullptr, __FUNCTION__, __FILE__, __LINE__, Color_Red4 };
    tracy::ScopedZone ___tracy_scoped_zone( &srcLocHere, 0, true );
    char message[1024] = {};
    int written = snprintf( message, sizeof( message ), "ERROR: %s FAILED with code %u (0x%x) | ", function, code, code );
    written += FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        code,
        MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
        (LPSTR)&message[written],
        sizeof(message) - written,
        NULL
    );
    fprintf( stderr, "%s\n", message );
    OutputDebugStringA( message );
    tracy::InitCallstackCritical();
    tracy::Profiler::LogString( MessageSourceType::Tracy, MessageSeverity::Error, Color_Red4, 60, written, message );
}

static BOOL TracySymFromAddr( HANDLE hProcess, DWORD64 Address, PDWORD64 Displacement, PSYMBOL_INFO Symbol )
{
    DBGHELP_SCOPED_LOCK;
    BOOL status = SymFromAddr( hProcess, Address, Displacement, Symbol );
#if DBGHELP_DEBUG_LEVEL >= 2
    if( status == FALSE )
        TracySymError( "SymFromAddr", GetLastError() );
#endif
    return status;
}

static BOOL TracySymGetLineFromAddr64( HANDLE hProcess, DWORD64 qwAddr, PDWORD pdwDisplacement, PIMAGEHLP_LINE64 Line64 )
{
    DBGHELP_SCOPED_LOCK;
    BOOL status = SymGetLineFromAddr64( hProcess, qwAddr, pdwDisplacement, Line64 );
#if DBGHELP_DEBUG_LEVEL >= 2
    if( status == FALSE )
        TracySymError( "SymGetLineFromAddr64", GetLastError() );
#endif
    return status;
}

static DWORD64 TracySymLoadModuleEx( HANDLE hProcess, HANDLE hFile, PCSTR ImageName, PCSTR ModuleName, DWORD64 BaseOfDll, DWORD DllSize, PMODLOAD_DATA Data, DWORD Flags ) {
    DBGHELP_SCOPED_LOCK;
    DWORD64 BaseAddress = SymLoadModuleEx( hProcess, hFile, ImageName, ModuleName, BaseOfDll, DllSize, Data, Flags );
#if DBGHELP_DEBUG_LEVEL >= 1
    if( BaseAddress == 0 ) {
        DWORD code = GetLastError();
        if( code != ERROR_SUCCESS )
        {
            char msg [512] = {};
            const char* modName = ModuleName ? ModuleName : (ImageName ? ImageName : "[NULL]");
            snprintf( msg, sizeof(msg), "SymLoadModuleEx for '%s'", modName );
            TracySymError( msg, GetLastError() );
        }
    }
#endif
    return BaseAddress;
}

static BOOL TracySymGetModuleInfo64(HANDLE hProcess, DWORD64 qwAddr, PIMAGEHLP_MODULE64 ModuleInfo)
{
    DBGHELP_SCOPED_LOCK;
    BOOL status = SymGetModuleInfo64( hProcess, qwAddr, ModuleInfo );
    if( status == FALSE )
        TracySymError( "SymGetModuleInfo64", GetLastError() );
    return status;
}

static BOOL TracyEnumProcessModules( HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded )
{
    BOOL status = EnumProcessModules( hProcess, lphModule, cb, lpcbNeeded );
    if( status == FALSE )
        TracySymError( "EnumProcessModules", GetLastError() );
    return status;
}

static BOOL TracyGetModuleInformation( HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb )
{
    BOOL status = GetModuleInformation( hProcess, hModule, lpmodinfo, cb );
    if( status == FALSE )
        TracySymError( "GetModuleInformation", GetLastError() );
    return status;
}

static DWORD TracyGetModuleFileNameA( HMODULE hModule, LPSTR lpFilename, DWORD nSize )
{
    BOOL status = GetModuleFileNameA( hModule, lpFilename, nSize );
    if( status == FALSE )
        TracySymError( "GetModuleFileNameA", GetLastError() );
    return status;
}

static DWORD TracySymAddrIncludeInlineTrace( HANDLE hProcess, DWORD64 Address )
{
#ifdef TRACY_NO_CALLSTACK_INLINES
    return 0;
#endif
    using SymAddrIncludeInlineTraceProc = decltype(TracySymAddrIncludeInlineTrace)(__stdcall*);
    static auto _SymAddrIncludeInlineTrace = (SymAddrIncludeInlineTraceProc)GetProcAddress(GetModuleHandleA("dbghelp.dll"), "SymAddrIncludeInlineTrace");
    if (!_SymAddrIncludeInlineTrace) return 0;
    DBGHELP_SCOPED_LOCK;
    // returns the number of inline frames at the address (plus the source frame),
    // or zero if no inline trace information is available for that address
    return _SymAddrIncludeInlineTrace( hProcess, Address );
}

static BOOL TracySymQueryInlineTrace( HANDLE hProcess, DWORD64 StartAddress, DWORD StartContext, DWORD64 StartRetAddress, DWORD64 CurAddress, LPDWORD CurContext, LPDWORD CurFrameIndex )
{
#ifdef TRACY_NO_CALLSTACK_INLINES
    return FALSE;
#endif
    using SymQueryInlineTraceProc = decltype(TracySymQueryInlineTrace)(__stdcall*);
    static auto _SymQueryInlineTrace = (SymQueryInlineTraceProc)GetProcAddress(GetModuleHandleA("dbghelp.dll"), "SymQueryInlineTrace");
    if (!_SymQueryInlineTrace) return FALSE;
    DBGHELP_SCOPED_LOCK;
    BOOL status = _SymQueryInlineTrace( hProcess, StartAddress, StartContext, StartRetAddress, CurAddress, CurContext, CurFrameIndex );
    if( status == FALSE )
        TracySymError( "SymQueryInlineTrace", GetLastError() );
    return status;
}

static BOOL TracySymFromInlineContext( HANDLE hProcess, DWORD64 Address, ULONG InlineContext, PDWORD64 Displacement, PSYMBOL_INFO Symbol )
{
#ifdef TRACY_NO_CALLSTACK_INLINES
    return FALSE;
#endif
    using SymFromInlineContextProc = decltype(TracySymFromInlineContext)(__stdcall*);
    static auto _SymFromInlineContext = (SymFromInlineContextProc)GetProcAddress(GetModuleHandleA("dbghelp.dll"), "SymFromInlineContext");
    if (!_SymFromInlineContext) return FALSE;
    DBGHELP_SCOPED_LOCK;
    BOOL status = _SymFromInlineContext( hProcess, Address, InlineContext, Displacement, Symbol );
    if( status == FALSE )
        TracySymError( "SymFromInlineContext", GetLastError() );
    return status;
}

static BOOL TracySymGetLineFromInlineContext( HANDLE hProcess, DWORD64 qwAddr, ULONG InlineContext, DWORD64 qwModuleBaseAddress, PDWORD pdwDisplacement, PIMAGEHLP_LINE64 Line64 )
{
#ifdef TRACY_NO_CALLSTACK_INLINES
    return FALSE;
#endif
    using SymGetLineFromInlineContextProc = decltype(TracySymGetLineFromInlineContext)(__stdcall*);
    static auto _SymGetLineFromInlineContext = (SymGetLineFromInlineContextProc)GetProcAddress(GetModuleHandleA("dbghelp.dll"), "SymGetLineFromInlineContext");
    if (!_SymGetLineFromInlineContext) return 0;
    DBGHELP_SCOPED_LOCK;
    BOOL status = _SymGetLineFromInlineContext( hProcess, qwAddr, InlineContext, qwModuleBaseAddress, pdwDisplacement, Line64 );
    if( status == FALSE )
        TracySymError( "SymGetLineFromInlineContext", GetLastError() );
    return status;
}

static void DbgHelpInit()
{
    // append executable path (and TRACY_SYMBOL_PATH) to the _NT_SYMBOL_PATH environment variable
    char buffer [32767];  // max env var length on Windows (including null-terminator)
    DWORD length = GetEnvironmentVariableA( "_NT_SYMBOL_PATH", buffer, sizeof( buffer ) );
    if( length > sizeof( buffer ) ) TracySymError( "GetEnvironmentVariableA", GetLastError() );
    else if( length + 1 >= sizeof( buffer ) ) TracySymError( "_TracyAppendEnvironmentVariable", ERROR_INSUFFICIENT_BUFFER );
    else
    {
        buffer[length] = ';';
        buffer[++length] = '\0';
        length += GetModuleFileNameA( NULL, &buffer[length], sizeof( buffer ) - length );
        if( length >= sizeof( buffer ) && GetLastError() == ERROR_INSUFFICIENT_BUFFER )
        {
            TracySymError( "GetModuleFileNameA", GetLastError() );
        }
        else
        {
            while( length > 0 && buffer[--length] != '\\' )
                buffer[length] = '\0';
            // now append TRACY_SYMBOL_PATH
            ++length;
            const int written = snprintf( &buffer[length], sizeof(buffer) - length, ";%s", TRACY_SYMBOL_PATH );
            if( written < 0 || written >= (int)( sizeof(buffer) - length ) )
                TracySymError( "_TracyAppendEnvironmentVariable", ERROR_INSUFFICIENT_BUFFER );
        }
    }

    assert( length < sizeof( buffer ) );
    if( SetEnvironmentVariableA( "_NT_SYMBOL_PATH", buffer ) == FALSE ) TracySymError( "SetEnvironmentVariableA", GetLastError() );
 
    DBGHELP_INIT;
    DBGHELP_SCOPED_LOCK;

    SymSetOptions( SymGetOptions() | SYMOPT_LOAD_LINES );
    if( SymInitialize( GetCurrentProcess(), NULL, TRUE ) == FALSE )
    {
        TracySymError( "SymInitialize", GetLastError() );
    }
    else if( GetModuleHandleA( "SymSrv.dll" ) == NULL )
    {
        TracyDebug( "SymSrv.dll was not loaded, it needs to be near a matching version of DbgHelp.dll. Symbol resolution may fail as symbol servers will not be used. See https://learn.microsoft.com/en-us/windows/win32/debug/calling-the-dbghelp-library" );
    }
}

static SYM_TYPE DbgHelpLoadSymbolsForModule( const char* imageName, uint64_t baseOfDll, uint32_t bllSize )
{
    // Value  SYM_TYPE      Inline  Lines  Description
    // -----  ------------  ------  -----  ---------------------------------------------------------
    //   0    SymNone         No      No   No symbols loaded; module found but no symbol info match.
    //   1    SymCoff         No     Ltd   COFF (.obj); legcy; coarse line table in section headers.
    //   2    SymCv           No     Yes   CodeView embedded in PE; has lines, but no S_INLINESITE.
    //   3    SymPdb          Yes    Yes   Full PDB; types, inlining, source lines, locals.
    //   4    SymExport       No      No   Names from PE export table only; no debug data.
    //   5    SymDeferred     N/A    N/A   Load deferred (SYMOPT_DEFERRED_LOADS); no data yet.
    //   6    SymSym          No     Ltd   Legacy .sym (DOS/Win16/Win95); unused in practice.
    //   7    SymDia          Yes    Yes   Loaded via DIA SDK COM; functionally equal to SymPdb.
    //   8    SymVirtual      ???    ???   Synthetic module (SLMFLAG_VIRTUAL); no file; for JIT.

    DWORD64 BaseAddress = TracySymLoadModuleEx( GetCurrentProcess(), nullptr, imageName, nullptr, baseOfDll, bllSize, nullptr, 0 );
    if ((BaseAddress == 0) && (GetLastError() != ERROR_SUCCESS)) return SymNone;
    IMAGEHLP_MODULE64 info = {};
    info.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if( TracySymGetModuleInfo64( GetCurrentProcess(), baseOfDll, &info ) == FALSE ) return SymNone;
    return info.SymType;
}

#undef DBGHELP_DEBUG_LEVEL
#undef DBGHELP_SCOPED_LOCK

}

#endif
