#include <limits>
#include <new>
#include <stdio.h>
#include <string.h>
#include "TracyDebug.hpp"
#include "TracyFastVector.hpp"
#include "TracyStringHelpers.hpp"
#include "../common/TracyAlloc.hpp"
#include "../common/TracySystem.hpp"
#  include "TracySymbols.hpp"

#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#include <algorithm>
#ifdef _MSC_VER
#  pragma warning( push )
#  pragma warning( disable : 4091 )
#endif
#include <dbghelp.h>
#pragma comment( lib, "dbghelp.lib" )
#ifdef _MSC_VER
#  pragma warning( pop )
#endif

#ifdef TRACY_DBGHELP_LOCK
#  include "TracyProfiler.hpp"

#  define DBGHELP_INIT TracyConcat( TRACY_DBGHELP_LOCK, Init() )
#  define DBGHELP_LOCK TracyConcat( TRACY_DBGHELP_LOCK, Lock() );
#  define DBGHELP_UNLOCK TracyConcat( TRACY_DBGHELP_LOCK, Unlock() );

extern "C"
{
    void DBGHELP_INIT;
    void DBGHELP_LOCK;
    void DBGHELP_UNLOCK;
};
#endif

namespace tracy
{

constexpr size_t MaxCbTrace = 64;
constexpr size_t MaxNameSize = 8*1024;

int cb_num;
CallstackEntry cb_data[MaxCbTrace];

extern "C"
{
    typedef DWORD (__stdcall *t_SymAddrIncludeInlineTrace)( HANDLE hProcess, DWORD64 Address );
    typedef BOOL (__stdcall *t_SymQueryInlineTrace)( HANDLE hProcess, DWORD64 StartAddress, DWORD StartContext, DWORD64 StartRetAddress, DWORD64 CurAddress, LPDWORD CurContext, LPDWORD CurFrameIndex );
    typedef BOOL (__stdcall *t_SymFromInlineContext)( HANDLE hProcess, DWORD64 Address, ULONG InlineContext, PDWORD64 Displacement, PSYMBOL_INFO Symbol );
    typedef BOOL (__stdcall *t_SymGetLineFromInlineContext)( HANDLE hProcess, DWORD64 qwAddr, ULONG InlineContext, DWORD64 qwModuleBaseAddress, PDWORD pdwDisplacement, PIMAGEHLP_LINE64 Line64 );

    t_SymAddrIncludeInlineTrace _SymAddrIncludeInlineTrace = 0;
    t_SymQueryInlineTrace _SymQueryInlineTrace = 0;
    t_SymFromInlineContext _SymFromInlineContext = 0;
    t_SymGetLineFromInlineContext _SymGetLineFromInlineContext = 0;
}

static void SymError( const char* function, DWORD code ) {
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
}

static void PrecacheProcessDriversAndModules();

void DbgHelpInit()
{
    if( ShouldResolveSymbolsOffline() ) return;

    _SymAddrIncludeInlineTrace = (t_SymAddrIncludeInlineTrace)GetProcAddress(GetModuleHandleA("dbghelp.dll"), "SymAddrIncludeInlineTrace");
    _SymQueryInlineTrace = (t_SymQueryInlineTrace)GetProcAddress(GetModuleHandleA("dbghelp.dll"), "SymQueryInlineTrace");
    _SymFromInlineContext = (t_SymFromInlineContext)GetProcAddress(GetModuleHandleA("dbghelp.dll"), "SymFromInlineContext");
    _SymGetLineFromInlineContext = (t_SymGetLineFromInlineContext)GetProcAddress(GetModuleHandleA("dbghelp.dll"), "SymGetLineFromInlineContext");

#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_INIT;
    DBGHELP_LOCK;
#endif

    // append executable path to the _NT_SYMBOL_PATH environment variable
    char buffer [32767];  // max env var length on Windows (including null-terminator)
    DWORD length = GetEnvironmentVariableA( "_NT_SYMBOL_PATH", buffer, sizeof( buffer ) );
    if( length > sizeof( buffer ) ) SymError( "GetEnvironmentVariableA", GetLastError() );
    else if( length + 1 >= sizeof( buffer ) ) SymError( "_TracyAppendEnvironmentVariable", ERROR_INSUFFICIENT_BUFFER );
    else
    {
        buffer[length] = ';';
        buffer[++length] = '\0';
        length += GetModuleFileNameA( NULL, &buffer[length], sizeof( buffer ) - length );
        if( length >= sizeof( buffer ) && GetLastError() == ERROR_INSUFFICIENT_BUFFER )
        {
            SymError( "GetModuleFileNameA", GetLastError() );
        }
        else
        {
            while( length > 0 && buffer[--length] != '\\' )
                buffer[length] = '\0';
        }
    }

    assert( length < sizeof( buffer ) );
    if( SetEnvironmentVariableA( "_NT_SYMBOL_PATH", buffer ) == FALSE ) SymError( "SetEnvironmentVariableA", GetLastError() );
 
    SymSetOptions( SymGetOptions() | SYMOPT_LOAD_LINES );
    if( SymInitialize( GetCurrentProcess(), NULL, TRUE ) == FALSE )
    {
        SymError( "SymInitialize", GetLastError() );
    }
    else if( GetModuleHandleA( "SymSrv.dll" ) == NULL )
    {
        TracyDebug( "SymSrv.dll was not loaded, it needs to be near a matching version of DbgHelp.dll. Symbol resolution may fail as symbol servers will not be used. See https://learn.microsoft.com/en-us/windows/win32/debug/calling-the-dbghelp-library" );
    }

    PrecacheProcessDriversAndModules();
#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_UNLOCK;
#endif
}

DWORD64 DbgHelpLoadSymbolsForModule( const char* imageName, uint64_t baseOfDll, uint32_t bllSize )
{
    if( s_shouldResolveSymbolsOffline ) return 0;
    return SymLoadModuleEx( GetCurrentProcess(), nullptr, imageName, nullptr, baseOfDll, bllSize, nullptr, 0 );
}

char* FormatImageName( const char* imageName, uint32_t imageNameLength )
{
    // when doing offline symbol resolution, we must store the full path of the dll for the resolving to work
    if( s_shouldResolveSymbolsOffline )
    {
        return CopyStringFast( imageName, imageNameLength );
    }
    else
    {
        const char* ptr = imageName + imageNameLength;
        while( ptr > imageName && *ptr != '\\' && *ptr != '/' ) ptr--;
        if( ptr > imageName ) ptr++;
        const auto namelen = imageName + imageNameLength - ptr;

        char* alloc = (char*)tracy_malloc_fast( namelen + 3 );
        alloc[0] = '[';
        memcpy( alloc + 1, ptr, namelen );
        alloc[namelen + 1] = ']';
        alloc[namelen + 2] = '\0';
        return alloc;
    }
}

ImageEntry* CacheModuleInfo( const char* imagePath, uint32_t imageNameLength, uint64_t baseOfDll, uint32_t dllSize )
{
    ImageEntry moduleEntry = {};
    moduleEntry.m_startAddress = baseOfDll;
    moduleEntry.m_endAddress = baseOfDll + dllSize;
    moduleEntry.m_path = CopyStringFast( imagePath, imageNameLength );
    moduleEntry.m_name = FormatImageName( imagePath, imageNameLength );

    return s_imageCache->AddEntry( moduleEntry );
}

ImageEntry* LoadSymbolsForModuleAndCache( const char* imagePath, uint32_t imageNameLength, uint64_t baseOfDll, uint32_t dllSize )
{
    DbgHelpLoadSymbolsForModule( imagePath, baseOfDll, dllSize );
    return CacheModuleInfo( imagePath, imageNameLength, baseOfDll, dllSize );
}

static void CacheProcessDrivers()
{
    DWORD needed;
    LPVOID dev[4096];
    if( EnumDeviceDrivers( dev, sizeof(dev), &needed ) != 0 )
    {
        char windir[MAX_PATH];
        if( !GetWindowsDirectoryA( windir, sizeof( windir ) ) ) memcpy( windir, "c:\\windows", 11 );
        const auto windirlen = strlen( windir );

        const auto sz = needed / sizeof( LPVOID );
        for( size_t i=0; i<sz; i++ )
        {
            char fn[MAX_PATH];
            const auto len = GetDeviceDriverBaseNameA( dev[i], fn, sizeof( fn ) );
            if( len != 0 )
            {
                auto buf = (char*)tracy_malloc_fast( len+3 );
                buf[0] = '<';
                memcpy( buf+1, fn, len );
                memcpy( buf+len+1, ">", 2 );
                
                ImageEntry kernelDriver{};
                kernelDriver.m_startAddress = (uint64_t)dev[i];
                kernelDriver.m_endAddress = 0;
                kernelDriver.m_name = buf;
                kernelDriver.m_path = nullptr;

                const auto len = GetDeviceDriverFileNameA( dev[i], fn, sizeof( fn ) );
                if( len != 0 )
                {
                    char full[MAX_PATH];
                    char* path = fn;

                    if( memcmp( fn, "\\SystemRoot\\", 12 ) == 0 )
                    {
                        memcpy( full, windir, windirlen );
                        strcpy( full + windirlen, fn + 11 );
                        path = full;
                    }

                    DbgHelpLoadSymbolsForModule( path, (DWORD64)dev[i], 0 );
                    
                    kernelDriver.m_path = CopyString( path );
                }

                s_krnlCache->AddEntry(kernelDriver);
            }
        }
        s_krnlCache->Sort();
    }
}

static void CacheProcessModules()
{
    DWORD needed;
    HANDLE proc = GetCurrentProcess();
    HMODULE mod[1024];
    if( EnumProcessModules( proc, mod, sizeof( mod ), &needed ) != 0 )
    {
        const auto sz = needed / sizeof( HMODULE );
        for( size_t i=0; i<sz; i++ )
        {
            MODULEINFO info;
            if( GetModuleInformation( proc, mod[i], &info, sizeof( info ) ) != 0 )
            {
                char name[1024];
                const auto nameLength = GetModuleFileNameA( mod[i], name, 1021 );
                if( nameLength > 0 )
                {
                    // This may be a new module loaded since our call to SymInitialize.
                    // Just in case, force DbgHelp to load its pdb !
                    LoadSymbolsForModuleAndCache( name, nameLength, (DWORD64)info.lpBaseOfDll, info.SizeOfImage );
                }
            }
        }
    }
}

static void PrecacheProcessDriversAndModules()
{
    // use TRACY_NO_DBGHELP_INIT_LOAD=1 to disable preloading of driver
    // and process module symbol loading at startup time - they will be loaded on demand later
    // Sometimes this process can take a very long time and prevent resolving callstack frames
    // symbols during that time.
    const char* noInitLoadEnv = GetEnvVar("TRACY_NO_DBGHELP_INIT_LOAD");
    const bool initTimeModuleLoad = !(noInitLoadEnv && noInitLoadEnv[0] == '1');
    if (!initTimeModuleLoad)
    {
        TracyDebug("TRACY: skipping init time dbghelper module load");
    }
    else
    {
        CacheProcessDrivers();
        CacheProcessModules();
    }
}

const char* DecodeCallstackPtrFast( uint64_t ptr )
{
    if( s_shouldResolveSymbolsOffline ) return "[unresolved]";

    static char ret[MaxNameSize];
    const auto proc = GetCurrentProcess();

    char buf[sizeof( SYMBOL_INFO ) + MaxNameSize];
    auto si = (SYMBOL_INFO*)buf;
    si->SizeOfStruct = sizeof( SYMBOL_INFO );
    si->MaxNameLen = MaxNameSize;

#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_LOCK;
#endif
    if( SymFromAddr( proc, ptr, nullptr, si ) == 0 )
    {
        *ret = '\0';
    }
    else
    {
        memcpy( ret, si->Name, si->NameLen );
        ret[si->NameLen] = '\0';
    }
#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_UNLOCK;
#endif
    return ret;
}

const char* GetKernelModulePath( uint64_t addr )
{
    assert( IsKernelAddress( addr ) );
    if( !s_krnlCache ) return nullptr;
    const ImageEntry* imageEntry = s_krnlCache->GetImageForAddress( addr );
    if( imageEntry ) return imageEntry->m_path;
    return nullptr;
}

struct ModuleNameAndBaseAddress
{
    const char* name;
    uint64_t baseAddr;
};

ModuleNameAndBaseAddress GetModuleNameAndPrepareSymbols( uint64_t addr )
{
    if( IsKernelAddress( addr ) )
    {
        const ImageEntry* entry = s_krnlCache->GetImageForAddress( addr );
        if( entry != nullptr ) return ModuleNameAndBaseAddress{ entry->m_name, entry->m_startAddress };
        return ModuleNameAndBaseAddress{ "<kernel>", addr };
    }

    const ImageEntry* entry = s_imageCache->GetImageForAddress( addr );
    if( entry != nullptr ) return ModuleNameAndBaseAddress{ entry->m_name, entry->m_startAddress };

    HANDLE proc = GetCurrentProcess();
    // Do not use FreeLibrary because we set the flag GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
    // see https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexa to get more information
    constexpr DWORD flag = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
    HMODULE mod = NULL;

    InitRpmalloc();
    if( GetModuleHandleExA( flag, (char*)addr, &mod ) != 0 )
    {
        MODULEINFO info;
        if( GetModuleInformation( proc, mod, &info, sizeof( info ) ) != 0 )
        {
            const auto base = uint64_t( info.lpBaseOfDll );
            if( addr >= base && addr < ( base + info.SizeOfImage ) )
            {
                char name[1024];
                const auto nameLength = GetModuleFileNameA( mod, name, sizeof( name ) );
                if( nameLength > 0 )
                {
                    // since this is the first time we encounter this module, load its symbols (needed for modules loaded after SymInitialize)
                    ImageEntry* cachedModule = LoadSymbolsForModuleAndCache( name, nameLength, (DWORD64)info.lpBaseOfDll, info.SizeOfImage );
                    return ModuleNameAndBaseAddress{ cachedModule->m_name, cachedModule->m_startAddress };
                }
            }
        }
    }

    return ModuleNameAndBaseAddress{ "[unknown]", 0x0 };
}

CallstackSymbolData DecodeSymbolAddress( uint64_t ptr )
{
    CallstackSymbolData sym;

    if( s_shouldResolveSymbolsOffline )
    {
        sym.file = "[unknown]";
        sym.line = 0;
        sym.needFree = false;
        return sym;
    }

    IMAGEHLP_LINE64 line;
    DWORD displacement = 0;
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_LOCK;
#endif
    const auto res = SymGetLineFromAddr64( GetCurrentProcess(), ptr, &displacement, &line );
    if( res == 0 || line.LineNumber >= 0xF00000 )
    {
        sym.file = "[unknown]";
        sym.line = 0;
        sym.needFree = false;
    }
    else
    {
        sym.file = CopyString( line.FileName );
        sym.line = line.LineNumber;
        sym.needFree = true;
    }
#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_UNLOCK;
#endif
    return sym;
}

static CallstackEntryData MakeUnresolvedCallstackEntryData( uint64_t ptr, ModuleNameAndBaseAddress moduleNameAndBaseAddress )
{
    cb_data[0].symAddr = ptr - moduleNameAndBaseAddress.baseAddr;
    cb_data[0].symLen = 0;

    cb_data[0].name = CopyStringFast( "[unresolved]" );
    cb_data[0].file = CopyStringFast( "[unknown]" );
    cb_data[0].line = 0;

    return { cb_data, 1, moduleNameAndBaseAddress.name };
}

CallstackEntryData DecodeCallstackPtr( uint64_t ptr )
{
#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_LOCK;
#endif

    InitRpmalloc();

    const ModuleNameAndBaseAddress moduleNameAndAddress = GetModuleNameAndPrepareSymbols( ptr );

    if( s_shouldResolveSymbolsOffline )
    {
#ifdef TRACY_DBGHELP_LOCK
        DBGHELP_UNLOCK;
#endif
        return MakeUnresolvedCallstackEntryData( ptr, moduleNameAndAddress );
    }

    int write;
    const auto proc = GetCurrentProcess();

#if !defined TRACY_NO_CALLSTACK_INLINES
    BOOL doInline = FALSE;
    DWORD ctx = 0;
    DWORD inlineNum = 0;
    if( _SymAddrIncludeInlineTrace )
    {
        inlineNum = _SymAddrIncludeInlineTrace( proc, ptr );
        if( inlineNum > MaxCbTrace - 1 ) inlineNum = MaxCbTrace - 1;
        DWORD idx;
        if( inlineNum != 0 ) doInline = _SymQueryInlineTrace( proc, ptr, 0, ptr, ptr, &ctx, &idx );
    }
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

    char buf[sizeof( SYMBOL_INFO ) + MaxNameSize];
    auto si = (SYMBOL_INFO*)buf;
    si->SizeOfStruct = sizeof( SYMBOL_INFO );
    si->MaxNameLen = MaxNameSize;

    const auto symValid = SymFromAddr( proc, ptr, nullptr, si ) != 0;

    IMAGEHLP_LINE64 line;
    DWORD displacement = 0;
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

    {
        const char* filename;
        const auto res = SymGetLineFromAddr64( proc, ptr, &displacement, &line );
        if( res == 0 || line.LineNumber >= 0xF00000 )
        {
            filename = "[unknown]";
            cb_data[write].line = 0;
        }
        else
        {
            filename = line.FileName;
            cb_data[write].line = line.LineNumber;
        }

        cb_data[write].name = symValid ? CopyStringFast( si->Name, si->NameLen ) : CopyStringFast( moduleNameAndAddress.name );
        cb_data[write].file = CopyStringFast( filename );
        if( symValid )
        {
            cb_data[write].symLen = si->Size;
            cb_data[write].symAddr = si->Address;
        }
        else
        {
            cb_data[write].symLen = 0;
            cb_data[write].symAddr = 0;
        }
    }

#if !defined TRACY_NO_CALLSTACK_INLINES
    if( doInline )
    {
        for( DWORD i=0; i<inlineNum; i++ )
        {
            auto& cb = cb_data[i];
            const auto symInlineValid = _SymFromInlineContext( proc, ptr, ctx, nullptr, si ) != 0;
            const char* filename;
            if( _SymGetLineFromInlineContext( proc, ptr, ctx, 0, &displacement, &line ) == 0 )
            {
                filename = "[unknown]";
                cb.line = 0;
            }
            else
            {
                filename = line.FileName;
                cb.line = line.LineNumber;
            }

            cb.name = symInlineValid ? CopyStringFast( si->Name, si->NameLen ) : CopyStringFast( moduleNameAndAddress.name );
            cb.file = CopyStringFast( filename );
            if( symInlineValid )
            {
                cb.symLen = si->Size;
                cb.symAddr = si->Address;
            }
            else
            {
                cb.symLen = 0;
                cb.symAddr = 0;
            }

            ctx++;
        }
    }
#endif
#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_UNLOCK;
#endif

    return { cb_data, uint8_t( cb_num ), moduleNameAndAddress.name };
}

} // namespace tracy