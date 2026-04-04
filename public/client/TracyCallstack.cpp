#include <limits>
#include <new>
#include <stdio.h>
#include <string.h>
#include "TracyCallstack.hpp"
#include "TracyDebug.hpp"
#include "TracyFastVector.hpp"
#include "TracyStringHelpers.hpp"
#include "../common/TracyAlloc.hpp"
#include "../common/TracySystem.hpp"
#include "TracySymbols.hpp"


#ifdef TRACY_HAS_CALLSTACK

#if TRACY_HAS_CALLSTACK == 1
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <psapi.h>
#  include "TracySymbolsDbgHelp.cpp"
#elif defined(TRACY_USE_LIBBACKTRACE)

#  include "../libbacktrace/backtrace.hpp"
#  include <algorithm>
#  include <dlfcn.h>
#  include <cxxabi.h>
#  include <stdlib.h>

#  ifdef __linux__
#    include "TracyElf.hpp"
#  endif

// Implementation files
#  include "../libbacktrace/alloc.cpp"
#  include "../libbacktrace/dwarf.cpp"
#  include "../libbacktrace/fileline.cpp"
#  include "../libbacktrace/mmapio.cpp"
#  include "../libbacktrace/posix.cpp"
#  include "../libbacktrace/sort.cpp"
#  include "../libbacktrace/state.cpp"
#  if TRACY_HAS_CALLSTACK == 4
#    include "../libbacktrace/macho.cpp"
#  else
#    include "../libbacktrace/elf.cpp"
#  endif
#  include "../common/TracyStackFrames.cpp"

#elif TRACY_HAS_CALLSTACK == 5
#  include <dlfcn.h>
#  include <cxxabi.h>
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

#if defined(TRACY_USE_LIBBACKTRACE) || TRACY_HAS_CALLSTACK == 5
// If you want to use your own demangling functionality (e.g. for another language),
// define TRACY_DEMANGLE and provide your own implementation of the __tracy_demangle
// function. The input parameter is a function name. The demangle function must
// identify whether this name is mangled, and fail if it is not. Failure is indicated
// by returning nullptr. If demangling succeeds, a pointer to the C string containing
// demangled function must be returned. The demangling function is responsible for
// managing memory for this string. It is expected that it will be internally reused.
// When a call to ___tracy_demangle is made, previous contents of the string memory
// do not need to be preserved. Function may return string of any length, but the
// profiler can choose to truncate it.
extern "C" const char* ___tracy_demangle( const char* mangled );

#ifndef TRACY_DEMANGLE
constexpr size_t ___tracy_demangle_buffer_len = 1024*1024;
char* ___tracy_demangle_buffer;

void ___tracy_init_demangle_buffer()
{
    ___tracy_demangle_buffer = (char*)tracy::tracy_malloc( ___tracy_demangle_buffer_len );
}

void ___tracy_free_demangle_buffer()
{
    tracy::tracy_free( ___tracy_demangle_buffer );
}

extern "C" const char* ___tracy_demangle( const char* mangled )
{
    if( !mangled || mangled[0] != '_' ) return nullptr;
    if( strlen( mangled ) > ___tracy_demangle_buffer_len ) return nullptr;
    int status;
    size_t len = ___tracy_demangle_buffer_len;
    return abi::__cxa_demangle( mangled, ___tracy_demangle_buffer, &len, &status );
}
#endif
#endif

namespace tracy
{
// TODO: move to TracySymbols.cpp
UserlandImageCache* s_imageCache;
ImageCache* s_krnlCache;

#ifdef __linux__

static constexpr uint32_t ExtPT_LOAD = 1;

struct ExternalImageEntry
{
    uint64_t startAddress;
    uint64_t endAddress;
    uint64_t loadBias;
    char* path;
    backtrace_state* btState;
    bool btAttempted;
};

static FastVector<ExternalImageEntry>* s_extImages = nullptr;
static pid_t s_externalPid = 0;
static bool s_extImagesSorted = true;

static uint64_t ReadElfMinLoadVaddr( const char* path )
{
    int fd = open( path, O_RDONLY );
    if( fd < 0 ) return UINT64_MAX;

    elf_ehdr ehdr;
    if( read( fd, &ehdr, sizeof( ehdr ) ) != sizeof( ehdr ) )
    {
        close( fd );
        return UINT64_MAX;
    }

    if( ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E' ||
        ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F' )
    {
        close( fd );
        return UINT64_MAX;
    }

    if( ehdr.e_phoff == 0 || ehdr.e_phnum == 0 )
    {
        close( fd );
        return UINT64_MAX;
    }

    if( lseek( fd, ehdr.e_phoff, SEEK_SET ) == (off_t)-1 )
    {
        close( fd );
        return UINT64_MAX;
    }

    uint64_t minVaddr = UINT64_MAX;
    for( uint16_t i = 0; i < ehdr.e_phnum; i++ )
    {
        elf_phdr phdr;
        if( read( fd, &phdr, sizeof( phdr ) ) != sizeof( phdr ) ) break;
        if( phdr.p_type == ExtPT_LOAD ) minVaddr = std::min( minVaddr, phdr.p_vaddr );
    }

    close( fd );
    return minVaddr;
}

static void ParseExternalProcMaps( pid_t pid )
{
    char mapPath[64];
    snprintf( mapPath, sizeof( mapPath ), "/proc/%d/maps", (int)pid );
    FILE* f = fopen( mapPath, "r" );
    if( !f ) return;

    char line[1024];
    while( fgets( line, sizeof( line ), f ) )
    {
        uint64_t start, end, offset;
        uint32_t devMaj, devMin;
        uint64_t inode;
        char perms[8];
        int consumed = 0;

        if( sscanf( line, "%lx-%lx %7s %lx %x:%x %lu %n", &start, &end, perms, &offset, &devMaj, &devMin, &inode, &consumed ) < 7 ) continue;
        if( !strchr( perms, 'x' ) ) continue;

        char* pathname = line + consumed;
        while( *pathname == ' ' || *pathname == '\t' ) pathname++;
        size_t plen = strlen( pathname );
        while( plen > 0 && ( pathname[plen-1] == '\n' || pathname[plen-1] == '\r' ) ) plen--;
        pathname[plen] = '\0';

        if( plen == 0 || pathname[0] != '/' ) continue;
        if( std::find_if( s_extImages->begin(), s_extImages->end(), [start]( const ExternalImageEntry& e ) { return e.startAddress == start; } ) != s_extImages->end() ) continue;

        uint64_t minVaddr = ReadElfMinLoadVaddr( pathname );
        uint64_t loadBias;
        if( minVaddr == UINT64_MAX )
        {
            loadBias = start;
        }
        else
        {
            uint64_t pageSize = sysconf( _SC_PAGESIZE );
            uint64_t alignedVaddr = minVaddr & ~(pageSize - 1);
            loadBias = start - alignedVaddr - offset;
        }

        ExternalImageEntry entry = {
            .startAddress = start,
            .endAddress = end,
            .loadBias = loadBias,
            .path = (char*)tracy_malloc( plen + 1 ),
            .btState = nullptr,
            .btAttempted = false
        };
        memcpy( entry.path, pathname, plen + 1 );

        s_extImagesSorted = false;
        s_extImages->push_next()[0] = entry;
    }

    fclose( f );

    if( !s_extImagesSorted )
    {
        std::sort( s_extImages->begin(), s_extImages->end(),
            []( const ExternalImageEntry& a, const ExternalImageEntry& b ) { return a.startAddress > b.startAddress; } );
        s_extImagesSorted = true;
    }
}

static const ExternalImageEntry* FindExternalImage( uint64_t address )
{
    if( !s_extImages || s_extImages->empty() ) return nullptr;

    auto it = std::lower_bound( s_extImages->begin(), s_extImages->end(), address,
        []( const ExternalImageEntry& e, uint64_t a ) { return e.startAddress > a; } );

    if( it != s_extImages->end() && address >= it->startAddress && address < it->endAddress )
    {
        return &*it;
    }
    return nullptr;
}

static const ExternalImageEntry* FindExternalImageRefresh( uint64_t address )
{
    auto entry = FindExternalImage( address );
    if( entry ) return entry;

    if( s_externalPid != 0 )
    {
        ParseExternalProcMaps( s_externalPid );
        return FindExternalImage( address );
    }
    return nullptr;
}

static void ExternalBacktraceErrorCb( void* data, const char* msg, int errnum )
{
}

static backtrace_state* GetExternalBtState( const ExternalImageEntry* entry )
{
    auto* e = const_cast<ExternalImageEntry*>( entry );
    if( e->btAttempted ) return e->btState;
    e->btAttempted = true;
    e->btState = backtrace_create_state_for_file( e->path, 0, ExternalBacktraceErrorCb, nullptr );
    return e->btState;
}

struct ExternalResolveData
{
    const char* name;
    const char* file;
    uint32_t line;
    int count;
};

static int ExternalPcInfoCb( void* data, uintptr_t pc, uintptr_t lowaddr, const char* filename, int lineno, const char* function )
{
    auto& rd = *(ExternalResolveData*)data;

    if( rd.count > 0 ) return 1;
    rd.count++;

    if( function )
    {
        const char* demangled = ___tracy_demangle( function );
        rd.name = demangled ? demangled : function;
    }
    else
    {
        rd.name = nullptr;
    }

    rd.file = filename;
    rd.line = lineno;

    return 0;
}

struct ExternalSymInfoData
{
    const char* symname;
    uintptr_t symval;
    uintptr_t symsize;
};

static void ExternalSymInfoCb( void* data, uintptr_t pc, const char* symname, uintptr_t symval, uintptr_t symsize )
{
    auto& sd = *(ExternalSymInfoData*)data;
    sd.symname = symname;
    sd.symval = symval;
    sd.symsize = symsize;
}

void InitExternalImageCache( pid_t pid )
{
    s_externalPid = pid;
    if( !s_extImages )
    {
        s_extImages = (FastVector<ExternalImageEntry>*)tracy_malloc( sizeof( FastVector<ExternalImageEntry> ) );
        new (s_extImages) FastVector<ExternalImageEntry>( 64 );
    }
    ParseExternalProcMaps( pid );
}

#endif // __linux__


#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
bool s_shouldResolveSymbolsOffline = false;
#endif // #ifdef TRACY_SYMBOL_OFFLINE_RESOLVE

#if TRACY_HAS_CALLSTACK == 1

extern "C"
{

    typedef unsigned long (__stdcall *___tracy_t_RtlWalkFrameChain)( void**, unsigned long, unsigned long );
    ___tracy_t_RtlWalkFrameChain ___tracy_RtlWalkFrameChainPtr = nullptr;
    TRACY_API unsigned long ___tracy_RtlWalkFrameChain( void** callers, unsigned long count, unsigned long flags)
    {
        return ___tracy_RtlWalkFrameChainPtr(callers, count, flags);
    }
}

void InitCallstackCritical()
{
    ___tracy_RtlWalkFrameChainPtr = (___tracy_t_RtlWalkFrameChain)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "RtlWalkFrameChain" );
}

void InitCallstack()
{
#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
    s_shouldResolveSymbolsOffline = ShouldResolveSymbolsOffline();
#endif //#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
    if( s_shouldResolveSymbolsOffline )
    {
        TracyDebug( "TRACY: enabling offline symbol resolving!" );
    }

    CreateImageCaches();

    DbgHelpInit();
}

void EndCallstack()
{
    DestroyImageCaches();
}

#elif defined(TRACY_USE_LIBBACKTRACE)

constexpr size_t MaxCbTrace = 64;

struct backtrace_state* cb_bts = nullptr;

int cb_num;
CallstackEntry cb_data[MaxCbTrace];
int cb_fixup;

#ifdef TRACY_DEBUGINFOD
debuginfod_client* s_debuginfod;

struct DebugInfo
{
    uint8_t* buildid;
    size_t buildid_size;
    char* filename;
    int fd;
};

static FastVector<DebugInfo>* s_di_known;
#endif

#ifdef __linux
struct KernelSymbol
{
    uint64_t addr;
    uint32_t size;
    const char* name;
    const char* mod;
};

KernelSymbol* s_kernelSym = nullptr;
size_t s_kernelSymCnt;

static void InitKernelSymbols()
{
    FILE* f = fopen( "/proc/kallsyms", "rb" );
    if( !f ) return;
    tracy::FastVector<KernelSymbol> tmpSym( 512 * 1024 );
    size_t linelen = 16 * 1024;     // linelen must be big enough to prevent reallocs in getline()
    auto linebuf = (char*)tracy_malloc( linelen );
    ssize_t sz;
    size_t validCnt = 0;
    while( ( sz = getline( &linebuf, &linelen, f ) ) != -1 )
    {
        auto ptr = linebuf;
        uint64_t addr = 0;
        while( *ptr != ' ' )
        {
            auto v = *ptr;
            if( v >= '0' && v <= '9' )
            {
                v -= '0';
            }
            else if( v >= 'a' && v <= 'f' )
            {
                v -= 'a';
                v += 10;
            }
            else if( v >= 'A' && v <= 'F' )
            {
                v -= 'A';
                v += 10;
            }
            else
            {
                assert( false );
            }
            assert( ( v & ~0xF ) == 0 );
            addr <<= 4;
            addr |= v;
            ptr++;
        }
        if( addr == 0 ) continue;
        ptr++;
        const bool valid = *ptr == 'T' || *ptr == 't';
        ptr += 2;
        const auto namestart = ptr;
        while( *ptr != '\t' && *ptr != '\n' ) ptr++;
        const auto nameend = ptr;
        const char* modstart = nullptr;
        const char* modend;
        if( *ptr == '\t' )
        {
            ptr += 2;
            modstart = ptr;
            while( *ptr != ']' ) ptr++;
            modend = ptr;
        }

        char* strname = nullptr;
        char* strmod = nullptr;

        if( valid )
        {
            validCnt++;

            strname = CopyStringFast( namestart, nameend - namestart );

            if( modstart )
            {
                strmod = CopyStringFast( modstart, modend - modstart );
            }
        }

        auto sym = tmpSym.push_next();
        sym->addr = addr;
        sym->size = 0;
        sym->name = strname;
        sym->mod = strmod;
    }
    tracy_free_fast( linebuf );
    fclose( f );
    if( tmpSym.empty() ) return;

    std::sort( tmpSym.begin(), tmpSym.end(), []( const KernelSymbol& lhs, const KernelSymbol& rhs ) { return lhs.addr < rhs.addr; } );
    for( size_t i=0; i<tmpSym.size()-1; i++ )
    {
        if( tmpSym[i].name ) tmpSym[i].size = tmpSym[i+1].addr - tmpSym[i].addr;
    }

    s_kernelSymCnt = validCnt;
    s_kernelSym = (KernelSymbol*)tracy_malloc_fast( sizeof( KernelSymbol ) * validCnt );
    auto dst = s_kernelSym;
    for( auto& v : tmpSym )
    {
        if( v.name ) *dst++ = v;
    }
    assert( dst == s_kernelSym + validCnt );

    TracyDebug( "Loaded %zu kernel symbols (%zu code sections)", tmpSym.size(), validCnt );
}
#endif

char* NormalizePath( const char* path )
{
    if( path[0] != '/' ) return nullptr;

    const char* ptr = path;
    const char* end = path + strlen( path );

    char* res = (char*)tracy_malloc( end - ptr + 1 );
    size_t rsz = 0;

    while( ptr < end )
    {
        const char* next = ptr;
        while( next < end && *next != '/' ) next++;
        size_t lsz = next - ptr;
        switch( lsz )
        {
        case 2:
            if( memcmp( ptr, "..", 2 ) == 0 )
            {
                const char* back = res + rsz - 1;
                while( back > res && *back != '/' ) back--;
                rsz = back - res;
                ptr = next + 1;
                continue;
            }
            break;
        case 1:
            if( *ptr == '.' )
            {
                ptr = next + 1;
                continue;
            }
            break;
        case 0:
            ptr = next + 1;
            continue;
        }
        if( rsz != 1 ) res[rsz++] = '/';
        memcpy( res+rsz, ptr, lsz );
        rsz += lsz;
        ptr = next + 1;
    }

    if( rsz == 0 )
    {
        memcpy( res, "/", 2 );
    }
    else
    {
        res[rsz] = '\0';
    }
    return res;
}

void InitCallstackCritical()
{
}

void InitCallstack()
{
    InitRpmalloc();

#ifdef TRACY_HAS_DL_ITERATE_PHDR_TO_REFRESH_IMAGE_CACHE
    CreateImageCaches();
#endif //#ifdef TRACY_HAS_DL_ITERATE_PHDR_TO_REFRESH_IMAGE_CACHE

#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
    s_shouldResolveSymbolsOffline = ShouldResolveSymbolsOffline();
#endif //#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
    if( s_shouldResolveSymbolsOffline )
    {
        cb_bts = nullptr; // disable use of libbacktrace calls
        TracyDebug( "TRACY: enabling offline symbol resolving!" );
    }
    else
    {
        cb_bts = backtrace_create_state( nullptr, 0, nullptr, nullptr );
    }

#ifndef TRACY_DEMANGLE
    ___tracy_init_demangle_buffer();
#endif

#ifdef __linux
    InitKernelSymbols();
#endif
#ifdef TRACY_DEBUGINFOD
    s_debuginfod = debuginfod_begin();
    s_di_known = (FastVector<DebugInfo>*)tracy_malloc( sizeof( FastVector<DebugInfo> ) );
    new (s_di_known) FastVector<DebugInfo>( 16 );
#endif
}

#ifdef TRACY_DEBUGINFOD
void ClearDebugInfoVector( FastVector<DebugInfo>& vec )
{
    for( auto& v : vec )
    {
        tracy_free( v.buildid );
        tracy_free( v.filename );
        if( v.fd >= 0 ) close( v.fd );
    }
    vec.clear();
}

DebugInfo* FindDebugInfo( FastVector<DebugInfo>& vec, const uint8_t* buildid_data, size_t buildid_size )
{
    for( auto& v : vec )
    {
        if( v.buildid_size == buildid_size && memcmp( v.buildid, buildid_data, buildid_size ) == 0 )
        {
            return &v;
        }
    }
    return nullptr;
}

int GetDebugInfoDescriptor( const char* buildid_data, size_t buildid_size, const char* filename )
{
    auto buildid = (uint8_t*)buildid_data;
    auto it = FindDebugInfo( *s_di_known, buildid, buildid_size );
    if( it ) return it->fd >= 0 ? dup( it->fd ) : -1;

    int fd = debuginfod_find_debuginfo( s_debuginfod, buildid, buildid_size, nullptr );
    it = s_di_known->push_next();
    it->buildid_size = buildid_size;
    it->buildid = (uint8_t*)tracy_malloc( buildid_size );
    memcpy( it->buildid, buildid, buildid_size );
    const auto fnsz = strlen( filename ) + 1;
    it->filename = (char*)tracy_malloc( fnsz );
    memcpy( it->filename, filename, fnsz );
    it->fd = fd >= 0 ? fd : -1;
    TracyDebug( "DebugInfo descriptor query: %i, fn: %s", fd, filename );
    return it->fd;
}

const uint8_t* GetBuildIdForImage( const char* image, size_t& size )
{
    assert( image );
    for( auto& v : *s_di_known )
    {
        if( strcmp( image, v.filename ) == 0 )
        {
            size = v.buildid_size;
            return v.buildid;
        }
    }
    return nullptr;
}

debuginfod_client* GetDebuginfodClient()
{
    return s_debuginfod;
}
#endif

void EndCallstack()
{
#ifdef TRACY_HAS_DL_ITERATE_PHDR_TO_REFRESH_IMAGE_CACHE
    DestroyImageCaches();
#endif //#ifdef TRACY_HAS_DL_ITERATE_PHDR_TO_REFRESH_IMAGE_CACHE
#ifndef TRACY_DEMANGLE
    ___tracy_free_demangle_buffer();
#endif
#ifdef TRACY_DEBUGINFOD
    ClearDebugInfoVector( *s_di_known );
    s_di_known->~FastVector<DebugInfo>();
    tracy_free( s_di_known );

    debuginfod_end( s_debuginfod );
#endif
}

#ifdef __linux__
static const char* DecodeCallstackPtrFastExternal( uint64_t ptr )
{
    static char ret[1024];
    auto vptr = (void*)ptr;
    const char* symname = nullptr;

    const auto* extImg = FindExternalImage( ptr );
    if( extImg )
    {
        auto* bts = GetExternalBtState( extImg );
        if( bts )
        {
            auto elfVaddr = (uintptr_t)( ptr - extImg->loadBias );
            ExternalSymInfoData sid = {};
            backtrace_syminfo( bts, elfVaddr, ExternalSymInfoCb, ExternalBacktraceErrorCb, &sid );
            if( sid.symname )
            {
                const char* demangled = ___tracy_demangle( sid.symname );
                symname = demangled ? demangled : sid.symname;
            }
        }
    }
    if( symname )
    {
        strncpy( ret, symname, sizeof( ret ) - 1 );
        ret[sizeof( ret ) - 1] = '\0';
    }
    else
    {
        *ret = '\0';
    }
    return ret;
}
#endif

const char* DecodeCallstackPtrFast( uint64_t ptr )
{
    static char ret[1024];

#ifdef __linux__
    if( s_externalPid != 0 && s_extImages ) return DecodeCallstackPtrFastExternal( ptr );
#endif

    auto vptr = (void*)ptr;
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

static int SymbolAddressDataCb( void* data, uintptr_t pc, uintptr_t lowaddr, const char* fn, int lineno, const char* function )
{
    auto& sym = *(CallstackSymbolData*)data;
    if( !fn )
    {
        sym.file = "[unknown]";
        sym.line = 0;
        sym.needFree = false;
    }
    else
    {
        sym.file = NormalizePath( fn );
        if( !sym.file ) sym.file = CopyString( fn );
        sym.line = lineno;
        sym.needFree = true;
    }

    return 1;
}

static void SymbolAddressErrorCb( void* data, const char* /*msg*/, int /*errnum*/ )
{
    auto& sym = *(CallstackSymbolData*)data;
    sym.file = "[unknown]";
    sym.line = 0;
    sym.needFree = false;
}

#ifdef __linux__
static CallstackSymbolData DecodeSymbolAddressExternal( uint64_t ptr )
{
    CallstackSymbolData sym;
    const auto* extImg = FindExternalImage( ptr );
    if( extImg )
    {
        auto* bts = GetExternalBtState( extImg );
        if( bts )
        {
            auto elfVaddr = (uintptr_t)( ptr - extImg->loadBias );
            backtrace_pcinfo( bts, elfVaddr, SymbolAddressDataCb, SymbolAddressErrorCb, &sym );
            return sym;
        }
    }
    SymbolAddressErrorCb( &sym, nullptr, 0 );
    return sym;
}
#endif

CallstackSymbolData DecodeSymbolAddress( uint64_t ptr )
{
    CallstackSymbolData sym;

#ifdef __linux__
    if( s_externalPid != 0 && s_extImages ) return DecodeSymbolAddressExternal( ptr );
#endif

    if( cb_bts )
    {
        backtrace_pcinfo( cb_bts, ptr, SymbolAddressDataCb, SymbolAddressErrorCb, &sym );
    }
    else
    {
        SymbolAddressErrorCb(&sym, nullptr, 0);
    }

    return sym;
}

static int CallstackDataCb( void* /*data*/, uintptr_t pc, uintptr_t lowaddr, const char* fn, int lineno, const char* function )
{
    cb_data[cb_num].symLen = 0;
    cb_data[cb_num].symAddr = (uint64_t)lowaddr;

    if( !fn && !function )
    {
        const char* symname = nullptr;
        auto vptr = (void*)pc;
        ptrdiff_t symoff = 0;

        Dl_info dlinfo;
        if( dladdr( vptr, &dlinfo ) )
        {
            symname = dlinfo.dli_sname;
            symoff = (char*)pc - (char*)dlinfo.dli_saddr;
            const char* demangled = ___tracy_demangle( symname );
            if( demangled ) symname = demangled;
        }

        if( !symname ) symname = "[unknown]";

        if( symoff == 0 )
        {
            const auto len = std::min<size_t>( strlen( symname ), std::numeric_limits<uint16_t>::max() );
            cb_data[cb_num].name = CopyStringFast( symname, len );
        }
        else
        {
            char buf[32];
            const auto offlen = sprintf( buf, " + %td", symoff );
            const auto namelen = std::min<size_t>( strlen( symname ), std::numeric_limits<uint16_t>::max() - offlen );
            auto name = (char*)tracy_malloc_fast( namelen + offlen + 1 );
            memcpy( name, symname, namelen );
            memcpy( name + namelen, buf, offlen );
            name[namelen + offlen] = '\0';
            cb_data[cb_num].name = name;
        }

        cb_data[cb_num].file = CopyStringFast( "[unknown]" );
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
            const char* demangled = ___tracy_demangle( function );
            if( demangled ) function = demangled;
        }

        const auto len = std::min<size_t>( strlen( function ), std::numeric_limits<uint16_t>::max() );
        cb_data[cb_num].name = CopyStringFast( function, len );
        cb_data[cb_num].file = NormalizePath( fn );
        if( !cb_data[cb_num].file ) cb_data[cb_num].file = CopyStringFast( fn );
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
        tracy_free_fast( (void*)cb_data[i].name );
        tracy_free_fast( (void*)cb_data[i].file );
    }

    cb_data[0].name = CopyStringFast( "[error]" );
    cb_data[0].file = CopyStringFast( "[error]" );
    cb_data[0].line = 0;

    cb_num = 1;
}

void SymInfoCallback( void* /*data*/, uintptr_t pc, const char* symname, uintptr_t symval, uintptr_t symsize )
{
    cb_data[cb_num-1].symLen = (uint32_t)symsize;
    cb_data[cb_num-1].symAddr = (uint64_t)symval;
}

void SymInfoError( void* /*data*/, const char* /*msg*/, int /*errnum*/ )
{
    cb_data[cb_num-1].symLen = 0;
    cb_data[cb_num-1].symAddr = 0;
}

void GetSymbolForOfflineResolve(void* address, uint64_t imageBaseAddress, CallstackEntry& cbEntry)
{
    // tagged with a string that we can identify as an unresolved symbol
    cbEntry.name = CopyStringFast( "[unresolved]" );
    // set .so relative offset so it can be resolved offline
    cbEntry.symAddr = (uint64_t)address - imageBaseAddress;
    cbEntry.symLen = 0x0;
    cbEntry.file = CopyStringFast( "[unknown]" );
    cbEntry.line = 0;
}

#ifdef __linux__
CallstackEntryData DecodeCallstackPtrExternal( uint64_t ptr )
{
    const auto* extImg = FindExternalImageRefresh( ptr );
    if( extImg )
    {
        const char* imageName = extImg->path;

        // Convert VMA (target process virtual address) to ELF virtual address.
        // elf_vaddr = vma - load_bias
        // libbacktrace indexes DWARF data by ELF virtual address when
        // the backtrace_state is created from a file (base_address=0).
        const auto elfVaddr = (uintptr_t)( ptr - extImg->loadBias );

        auto* bts = GetExternalBtState( extImg );
        if( bts )
        {
            // Try DWARF-based resolution
            ExternalResolveData rd = {};
            backtrace_pcinfo( bts, elfVaddr, ExternalPcInfoCb, ExternalBacktraceErrorCb, &rd );

            if( rd.name || rd.file )
            {
                cb_num = 1;
                if( rd.name )
                {
                    const auto len = std::min<size_t>( strlen( rd.name ), std::numeric_limits<uint16_t>::max() );
                    cb_data[0].name = CopyStringFast( rd.name, len );
                }
                else
                {
                    cb_data[0].name = CopyStringFast( "[unknown]" );
                }
                if( rd.file )
                {
                    cb_data[0].file = NormalizePath( rd.file );
                    if( !cb_data[0].file ) cb_data[0].file = CopyStringFast( rd.file );
                }
                else
                {
                    cb_data[0].file = CopyStringFast( "[unknown]" );
                }
                cb_data[0].line = rd.line;
                cb_data[0].symLen = 0;
                cb_data[0].symAddr = elfVaddr;

                // Try to get symbol size info
                ExternalSymInfoData sid = {};
                backtrace_syminfo( bts, elfVaddr, ExternalSymInfoCb, ExternalBacktraceErrorCb, &sid );
                if( sid.symsize > 0 )
                {
                    cb_data[0].symLen = (uint32_t)sid.symsize;
                    cb_data[0].symAddr = (uint64_t)sid.symval;
                }

                // If DWARF gave us no function name, try the symbol table
                if( !rd.name && sid.symname )
                {
                    tracy_free_fast( (void*)cb_data[0].name );
                    const char* demangled = ___tracy_demangle( sid.symname );
                    if( demangled )
                    {
                        cb_data[0].name = CopyStringFast( demangled );
                    }
                    else
                    {
                        cb_data[0].name = CopyStringFast( sid.symname );
                    }
                }

                return { cb_data, 1, imageName ? imageName : "[unknown]" };
            }

            // DWARF resolution failed; try symtab-only fallback
            ExternalSymInfoData sid = {};
            backtrace_syminfo( bts, elfVaddr, ExternalSymInfoCb, ExternalBacktraceErrorCb, &sid );
            if( sid.symname )
            {
                cb_num = 1;
                const char* demangled = ___tracy_demangle( sid.symname );
                cb_data[0].name = CopyStringFast( demangled ? demangled : sid.symname );
                cb_data[0].file = CopyStringFast( imageName ? imageName : "[unknown]" );
                cb_data[0].line = 0;
                cb_data[0].symLen = (uint32_t)sid.symsize;
                cb_data[0].symAddr = (uint64_t)sid.symval;
                return { cb_data, 1, imageName ? imageName : "[unknown]" };
            }
        }

        // Fallback: return unresolved with offset
        cb_num = 1;
        cb_data[0].name = CopyStringFast( "[unresolved]" );
        cb_data[0].file = CopyStringFast( imageName ? imageName : "[unknown]" );
        cb_data[0].line = 0;
        cb_data[0].symLen = 0;
        cb_data[0].symAddr = elfVaddr;
        return { cb_data, 1, imageName ? imageName : "[unknown]" };
    }

    // Address doesn't belong to any known mapping
    cb_num = 1;
    cb_data[0].name = CopyStringFast( "[unknown]" );
    cb_data[0].file = CopyStringFast( "[unknown]" );
    cb_data[0].line = 0;
    cb_data[0].symLen = 0;
    cb_data[0].symAddr = ptr;
    return { cb_data, 1, "[unknown]" };
}
#endif

CallstackEntryData DecodeCallstackPtr( uint64_t ptr )
{
    InitRpmalloc();
    if( !IsKernelAddress( ptr ) )
    {
#ifdef __linux__
        if( s_externalPid != 0 && s_extImages ) return DecodeCallstackPtrExternal( ptr );
#endif

        const char* imageName = nullptr;
        uint64_t imageBaseAddress = 0x0;

#ifdef TRACY_HAS_DL_ITERATE_PHDR_TO_REFRESH_IMAGE_CACHE
        const auto* image = s_imageCache->GetImageForAddress( ptr );
        if( image )
        {
            imageName = image->m_name;
            imageBaseAddress = uint64_t( image->m_startAddress );
        }
#else
        Dl_info dlinfo;
        if( dladdr( (void*)ptr, &dlinfo ) )
        {
            imageName = dlinfo.dli_fname;
            imageBaseAddress = uint64_t( dlinfo.dli_fbase );
        }
#endif

        if( s_shouldResolveSymbolsOffline )
        {
            cb_num = 1;
            GetSymbolForOfflineResolve( (void*)ptr, imageBaseAddress, cb_data[0] );
        }
        else
        {
            cb_num = 0;
            backtrace_pcinfo( cb_bts, ptr, CallstackDataCb, CallstackErrorCb, nullptr );
            assert( cb_num > 0 );

            backtrace_syminfo( cb_bts, ptr, SymInfoCallback, SymInfoError, nullptr );
        }

        return { cb_data, uint8_t( cb_num ), imageName ? imageName : "[unknown]" };
    }
#ifdef __linux
    else if( s_kernelSym )
    {
        auto it = std::lower_bound( s_kernelSym, s_kernelSym + s_kernelSymCnt, ptr, []( const KernelSymbol& lhs, const uint64_t& rhs ) { return lhs.addr + lhs.size < rhs; } );
        if( it != s_kernelSym + s_kernelSymCnt )
        {
            cb_data[0].name = CopyStringFast( it->name );
            cb_data[0].file = CopyStringFast( "<kernel>" );
            cb_data[0].line = 0;
            cb_data[0].symLen = it->size;
            cb_data[0].symAddr = it->addr;
            return { cb_data, 1, it->mod ? it->mod : "<kernel>" };
        }
    }
#endif

    cb_data[0].name = CopyStringFast( "[unknown]" );
    cb_data[0].file = CopyStringFast( "<kernel>" );
    cb_data[0].line = 0;
    cb_data[0].symLen = 0;
    cb_data[0].symAddr = 0;
    return { cb_data, 1, "<kernel>" };
}

#elif TRACY_HAS_CALLSTACK == 5

void InitCallstackCritical()
{
}

void InitCallstack()
{
    ___tracy_init_demangle_buffer();
}

void EndCallstack()
{
    ___tracy_free_demangle_buffer();
}

const char* DecodeCallstackPtrFast( uint64_t ptr )
{
    static char ret[1024];
    auto vptr = (void*)ptr;
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

CallstackSymbolData DecodeSymbolAddress( uint64_t ptr )
{
    const char* symloc = nullptr;
    Dl_info dlinfo;
    if( dladdr( (void*)ptr, &dlinfo ) ) symloc = dlinfo.dli_fname;
    if( !symloc ) symloc = "[unknown]";
    return CallstackSymbolData { symloc, 0, false, 0 };
}

CallstackEntryData DecodeCallstackPtr( uint64_t ptr )
{
    static CallstackEntry cb;
    cb.line = 0;

    const char* symname = nullptr;
    const char* symloc = nullptr;
    auto vptr = (void*)ptr;
    ptrdiff_t symoff = 0;
    void* symaddr = nullptr;

    Dl_info dlinfo;
    if( dladdr( vptr, &dlinfo ) )
    {
        symloc = dlinfo.dli_fname;
        symname = dlinfo.dli_sname;
        symoff = (char*)ptr - (char*)dlinfo.dli_saddr;
        symaddr = dlinfo.dli_saddr;
        const char* demangled = ___tracy_demangle( symname );
        if( demangled ) symname = demangled;
    }

    if( !symname ) symname = "[unknown]";
    if( !symloc ) symloc = "[unknown]";

    if( symoff == 0 )
    {
        const auto len = std::min<size_t>( strlen( symname ), std::numeric_limits<uint16_t>::max() );
        cb.name = CopyString( symname, len );
    }
    else
    {
        char buf[32];
        const auto offlen = sprintf( buf, " + %td", symoff );
        const auto namelen = std::min<size_t>( strlen( symname ), std::numeric_limits<uint16_t>::max() - offlen );
        auto name = (char*)tracy_malloc( namelen + offlen + 1 );
        memcpy( name, symname, namelen );
        memcpy( name + namelen, buf, offlen );
        name[namelen + offlen] = '\0';
        cb.name = name;
    }

    cb.file = CopyString( "[unknown]" );
    cb.symLen = 0;
    cb.symAddr = (uint64_t)symaddr;

    return { &cb, 1, symloc };
}

#endif

}

#endif
