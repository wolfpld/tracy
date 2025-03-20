#include <cstddef>
#include <limits>
#include <new>
#include <stdio.h>
#include <string.h> // for memcpy
#include <assert.h>
#include <string_view>
#include <sys/types.h>

#include "TracyCallstack.hpp"
#include "TracyAlign.hpp"
#include "TracyDebug.hpp"
#include "TracyStringHelpers.hpp"
#include "TracyAlloc.hpp"
#include "TracySystem.hpp"
#include "TracyDebugModulesHeaderFile.hpp"

#ifdef TRACY_HAS_CALLSTACK

#if TRACY_HAS_CALLSTACK == 1
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <psapi.h>
#  include <algorithm>
#  ifdef _MSC_VER
#    pragma warning( push )
#    pragma warning( disable : 4091 )
#  endif
#  include <dbghelp.h>
#  pragma comment( lib, "dbghelp.lib" )
#  ifdef _MSC_VER
#    pragma warning( pop )
#  endif
#elif defined(TRACY_USE_LIBBACKTRACE)

#  include "../libbacktrace/backtrace.hpp"
#  include <algorithm>
#  include <dlfcn.h>
#  include <cxxabi.h>
#  include <stdlib.h>

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
#  include "TracyStackFrames.cpp"

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

#if defined(TRACY_USE_LIBBACKTRACE) && TRACY_HAS_CALLSTACK != 4 // dl_iterate_phdr is required for the current image cache. Need to move it to libbacktrace?
#   define TRACY_USE_IMAGE_CACHE
#   include <link.h>
struct BuildIdNote {
    ElfW(Nhdr) nhdr;

    char name[4];
    uint8_t build_id[0];
};
#endif

namespace tracy
{

    inline bool GetEnvBool( const char* environementVariableName, bool defaultValue )
    {
        const char* v = GetEnvVar( environementVariableName );
        if (v) return v[0] == '1';
        else return defaultValue;
    }

    // when "TRACY_SYMBOL_OFFLINE_RESOLVE" is set, instead of fully resolving symbols at runtime,
    // simply resolve the offset and image name (which will be enough the resolving to be done offline)
#ifdef TRACY_SYMBOL_OFFLINE_RESOLVE
    static bool s_shouldResolveSymbolsOffline = true;
#else
    static bool s_shouldResolveSymbolsOffline = false;
#endif // TRACY_SYMBOL_OFFLINE_RESOLVE
    void PreventSymbolResolution() { s_shouldResolveSymbolsOffline = true; }

    inline bool IsKernelAddress( uint64_t addr ) {
        return (addr >> 63) != 0;
    }

    void DestroyImageEntry( ImageEntry& entry )
    {
        tracy_free_fast( entry.path );
        entry.path = nullptr;
        tracy_free_fast( entry.name );
        entry.name = nullptr;
        tracy_free( entry.imageDebugInfo.debugData );
        entry.imageDebugInfo.debugData = nullptr;
    }

    class ImageCache
    {
    public:
        ImageCache( size_t moduleCacheCapacity = 512 ) : m_modCache( moduleCacheCapacity ) 
        {
            for (auto& it : m_modCache) 
            {
                it.start = 0;
                it.end = 0;
                it.name = nullptr;
                it.path = nullptr;

                it.imageDebugInfo.debugData = nullptr;
                it.imageDebugInfo.debugDataSize = 0;
                it.imageDebugInfo.debugFormat = ImageDebugFormatId::NoDebugFormat;
            }            
        }
        ~ImageCache() { Clear(); }

        ImageEntry* CacheModuleWithDebugInfo( const ImageEntry& entry )
        {
            m_sorted &= m_modCache.empty() ? true : (entry.start < m_modCache.back().start);
            ImageEntry* newEntry = m_modCache.push_next();
            *newEntry = entry;
            return newEntry;
        }

        const ImageEntry* FindEntryFromAddr( uint64_t addr ) const
        {
            if( m_sorted )
            {
                auto it = std::lower_bound( m_modCache.begin(), m_modCache.end(), addr, []( const ImageEntry& lhs, const uint64_t& rhs ) { return lhs.start > rhs; } );
                if( it != m_modCache.end() && ( addr < it->end || it->end == 0 ) )
                    return &(*it);
            }
            else
            {
                auto it = std::find_if( m_modCache.begin(), m_modCache.end(), [addr]( const ImageEntry& module ) { return addr >= module.start && ( addr < module.end || module.end == 0 ); } );
                if( it != m_modCache.end() )
                    return &(*it);
            }
            return nullptr;
        }

        void Sort()
        {
            if( !m_sorted )
            {
                std::sort( m_modCache.begin(), m_modCache.end(), []( const ImageEntry& lhs, const ImageEntry& rhs ) { return lhs.start > rhs.start; } );
                m_sorted = true;
            }
        }

        void Clear()
        {
            for( ImageEntry& cacheEntry : m_modCache )
            {
                DestroyImageEntry( cacheEntry );
            }
            m_modCache.clear();
            m_sorted = true;
        }

        bool ContainsModule( uint64_t startAddress )
        {
            const ImageEntry* moduleInfo = FindEntryFromAddr( startAddress );
            return moduleInfo && moduleInfo->start == startAddress;
        }

        const FastVector<ImageEntry>& GetModuleData() const
        {
            return m_modCache;
        }
    protected:
        FastVector<ImageEntry> m_modCache;
        bool m_sorted = true;
    };


    // The only threads that access the cache are the Symbol Worker and the Tracy Thread
    // Only the symbol worker may write, but the Tracy Thread needs to be able to read the cache safely
    // Since only the SymbolWorker is allowed to write the cache, it does not need to lock when reading.
    static std::recursive_mutex s_cacheMutex;
    std::recursive_mutex& GetModuleCacheMutexForRead() {
        return s_cacheMutex;
    }

#if defined(TRACY_USE_IMAGE_CACHE)
// when we have access to dl_iterate_phdr(), we can build a cache of address ranges to image paths
// so we can quickly determine which image an address falls into.
// We refresh this cache only when we hit an address that doesn't fall into any known range.


class ImageCacheLibbacktrace : public ImageCache
{
public:
    ImageCacheLibbacktrace()
        : ImageCache()
    {
        Refresh();
    }

    ~ImageCacheLibbacktrace()
    {
        m_haveMainImageName = false;
    }

    const ImageEntry* GetImageForAddress( uint64_t address )
    {
        const ImageEntry* entry = FindEntryFromAddr( address );

        if( !entry )
        {
            Refresh();
            return FindEntryFromAddr( address );
        }
        return entry;
    }

private:
    bool m_updated = false;
    bool m_haveMainImageName = false;

    // success return 0
    // failed return 1
    static int GetBuildIdNoteFromNote( ImageEntry* imageEntry, BuildIdNote* note, ptrdiff_t fileLen)
    {
        auto& nhdr = note->nhdr;

        while( fileLen >= sizeof(BuildIdNote) )
        {
            if (nhdr.n_type == NT_GNU_BUILD_ID &&
                nhdr.n_descsz != 0 &&
                nhdr.n_namesz == 4 &&
                memcmp(note->name, "GNU", 4) == 0)
            {
                imageEntry->imageDebugInfo.debugFormat = ImageDebugFormatId::ElfDebugFormat;
                imageEntry->imageDebugInfo.debugDataSize = nhdr.n_descsz; 
                imageEntry->imageDebugInfo.debugData = (uint8_t*)tracy_malloc(imageEntry->imageDebugInfo.debugDataSize);
                memcpy(imageEntry->imageDebugInfo.debugData, &note->build_id[0], imageEntry->imageDebugInfo.debugDataSize);

                return 0;
            }

            const size_t offset = sizeof(ElfW(Nhdr))
                + tracy::Align(note->nhdr.n_namesz, 4)
                + tracy::Align(note->nhdr.n_descsz, 4);

            note = reinterpret_cast<BuildIdNote*>((char *)note + offset);
            fileLen -= offset;
        }

        return 1;
    }

    static int Callback( struct dl_phdr_info* info, size_t size, void* data )
    {
        ImageCacheLibbacktrace* cache = reinterpret_cast<ImageCacheLibbacktrace*>( data );

        const uint64_t startAddress = reinterpret_cast<uint64_t>( info->dlpi_addr );
        if( cache->ContainsModule( startAddress ) ) return 0;

        const uint32_t headerCount = info->dlpi_phnum;
        assert( headerCount > 0);
        const uint64_t endAddress = reinterpret_cast<uint64_t>( info->dlpi_addr +
            info->dlpi_phdr[info->dlpi_phnum - 1].p_vaddr + info->dlpi_phdr[info->dlpi_phnum - 1].p_memsz);

        ImageEntry image{};
        image.start = startAddress;
        image.end = endAddress;
      
        // the base executable name isn't provided when iterating with dl_iterate_phdr,
        // we will have to patch the executable image name outside this callback
        image.name = info->dlpi_name && info->dlpi_name[0] != '\0' ? CopyStringFast(info->dlpi_name) :  nullptr;

        
        for (unsigned i = 0; i < info->dlpi_phnum; i++) 
        {
            if (info->dlpi_phdr[i].p_type != PT_NOTE)
                continue;
    
            void* raw =  (void*)(info->dlpi_addr +
                info->dlpi_phdr[i].p_vaddr);

            ptrdiff_t len = info->dlpi_phdr[i].p_filesz;

            if (GetBuildIdNoteFromNote(&image, static_cast<BuildIdNote*>(raw), len) == 0)
                break;
            

        }
        
        cache->CacheModuleWithDebugInfo(image);
        cache->m_updated = true;

        return 0;
    }

 

    void Refresh()
    {
        m_updated = false;
        dl_iterate_phdr( Callback, this );

        if( m_updated )
        {
            Sort();
            // patch the main executable image name here, as calling dl_* functions inside the dl_iterate_phdr callback might cause deadlocks
            UpdateMainImageName();
        }
    }

    void UpdateMainImageName()
    {
        if( m_haveMainImageName )
        {
            return;
        }

        for( ImageEntry& entry : m_modCache )
        {
            if( entry.name == nullptr )
            {
                Dl_info dlInfo;
                if( dladdr( (void *)entry.start, &dlInfo ) )
                {
                    if( dlInfo.dli_fname )
                    {
                        entry.name = CopyStringFast(dlInfo.dli_fname);
                    }
                }

                // we only expect one entry to be null for the main executable entry
                break;
            }
        }

        m_haveMainImageName = true;
    }

    void Clear()
    {
        ImageCache::Clear();
        m_haveMainImageName = false;
    }
};
#endif // defined(TRACY_USE_IMAGE_CACHE)


#ifdef TRACY_USE_IMAGE_CACHE
typedef ImageCacheLibbacktrace UserlandImageCache;
#else
typedef ImageCache UserlandImageCache;
#endif //#ifdef TRACY_USE_IMAGE_CACHE

static UserlandImageCache* s_imageCache = nullptr;
static ImageCache* s_krnlCache = nullptr;

#ifdef __linux
static ImageCache* s_krnlSymbolsCache = nullptr;
#endif

const ImageEntry* GetImageEntryFromPtr(uint64_t ptr)
{
    if(IsKernelAddress(ptr))
    {
        return s_krnlCache->FindEntryFromAddr(ptr);
    }
    else return s_imageCache->FindEntryFromAddr(ptr);
}

void CreateImageCaches()
{
    assert( s_imageCache == nullptr && s_krnlCache == nullptr );
    s_imageCache = new ( tracy_malloc( sizeof( UserlandImageCache ) ) ) UserlandImageCache();
    s_krnlCache = new ( tracy_malloc( sizeof( ImageCache ) ) ) ImageCache();

  
}

void DestroyImageCaches()
{
    if ( s_krnlCache != nullptr )
    {
        s_krnlCache->~ImageCache();
        tracy_free( (void*)s_krnlCache );
        s_krnlCache = nullptr;
    }

    if ( s_imageCache != nullptr )
    {
        s_imageCache->~UserlandImageCache();
        tracy_free( s_imageCache );
        s_imageCache = nullptr;
    }

}

const FastVector<ImageEntry>* GetUserImageInfos()
{
    return &s_imageCache->GetModuleData();
}

const FastVector<ImageEntry>* GetKernelImageInfos()
{
    return &s_krnlCache->GetModuleData();
}

void FormatImageName(char** moduleCacheName, const char* imageName, uint32_t imageNameLength)
{
    auto ptr = imageName + imageNameLength;
    while (ptr > imageName && *ptr != '\\' && *ptr != '/') ptr--;
    if (ptr > imageName) ptr++;
    const auto namelen = imageName + imageNameLength - ptr;
    *moduleCacheName = (char*)tracy_malloc_fast(namelen + 3);
    (*moduleCacheName)[0] = '[';
    memcpy(*moduleCacheName + 1, ptr, namelen);
    (*moduleCacheName)[namelen + 1] = ']';
    (*moduleCacheName)[namelen + 2] = '\0';
}

#if TRACY_HAS_CALLSTACK == 1

enum { MaxCbTrace = 64 };
enum { MaxNameSize = 8*1024 };

int cb_num;
CallstackEntry cb_data[MaxCbTrace];

HANDLE s_DbgHelpSymHandle = 0;

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

    TRACY_API ___tracy_t_RtlWalkFrameChain ___tracy_RtlWalkFrameChain = 0;
}

struct CV_INFO_PDB70
{
    DWORD CvSignature;
    GUID Signature;
    DWORD Age;
    BYTE PdbFileName[1];
};

static constexpr DWORD CV_SIGNATURE_RSDS = 'SDSR'; // 'SDSR'

bool GetModuleInfoFromPEHeaders( uint64_t baseOfDll, ImageDebugFormatId* debugFormat, uint8_t** debugInformationData, uint32_t* debugInformationSize )
{
    static constexpr bool MappedAsImage = true;

    PVOID BaseAddress = (void*)baseOfDll;

    PIMAGE_NT_HEADERS header = ImageNtHeader( BaseAddress );

    ULONG debugDirectoryCount = 0;
    IMAGE_SECTION_HEADER* debugSectionHeader;

    PVOID debugSectionData = ImageDirectoryEntryToDataEx( BaseAddress, true, IMAGE_DIRECTORY_ENTRY_DEBUG,
        &debugDirectoryCount, &debugSectionHeader );

    if( debugSectionData == NULL )
    {
        return false;
    }
    IMAGE_DEBUG_DIRECTORY* debugDirectory = static_cast<IMAGE_DEBUG_DIRECTORY*>( debugSectionData );

    for( size_t i=0; (i * sizeof( IMAGE_DEBUG_DIRECTORY ) ) < debugDirectoryCount; i++ )
    {

        const IMAGE_DEBUG_DIRECTORY& curDebugDirectory = debugDirectory[i];

        if( debugDirectory[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW ) continue;

        CV_INFO_PDB70* pData = (CV_INFO_PDB70*)(uintptr_t( BaseAddress ) + 
            ( MappedAsImage 
            ? debugDirectory[i].AddressOfRawData
            : debugDirectory[i].PointerToRawData)
            );

        if( pData->CvSignature != CV_SIGNATURE_RSDS ) continue;

        *debugFormat = ImageDebugFormatId::PdbDebugFormat;

        const uint32_t pdbFileLength = strlen( (const char*)pData->PdbFileName );
        const uint32_t debugFormatSize = sizeof( PEImageDebugData ) + pdbFileLength + 1;
        *debugInformationData = (uint8_t*)tracy_malloc( debugFormatSize );
        *debugInformationSize = debugFormatSize;

        uint8_t* ptrToDebugPacket = reinterpret_cast<uint8_t*>( *debugInformationData );
        PEImageDebugData* ptrToWindowsDebugData = reinterpret_cast<PEImageDebugData*>( ptrToDebugPacket );

        // write minor major version
        ptrToWindowsDebugData->majorVersion = curDebugDirectory.MajorVersion;
        ptrToWindowsDebugData->minorVersion = curDebugDirectory.MinorVersion;

        ptrToWindowsDebugData->exeDataTimeStamp = curDebugDirectory.TimeDateStamp;
        ptrToWindowsDebugData->cvInfo.Age = pData->Age;
        ptrToWindowsDebugData->cvInfo.CvSignature = pData->CvSignature;
        static_assert( sizeof( GUID ) == sizeof( pData->Signature ), "GUID size must match" );
        memcpy( &ptrToWindowsDebugData->cvInfo.Signature, &pData->Signature, sizeof( pData->Signature ) );
        memcpy( ptrToDebugPacket + sizeof( PEImageDebugData ), pData->PdbFileName, pdbFileLength + 1 );

        return true;
    }
    return false;
}

void GetModuleInfoFromDbgHelp( const char* imageName, ImageEntry* moduleEntry )
{
    IMAGEHLP_MODULE64 moduleInfo{};
    moduleInfo.SizeOfStruct = sizeof( IMAGEHLP_MODULE64 );
    if( TRUE == SymGetModuleInfo64( s_DbgHelpSymHandle, moduleEntry->start, &moduleInfo ) )
    {
        if( moduleInfo.SymType == SymDeferred ) // If symbol loading was deferred, force load it so that we can retrieve the debug informations
        {
            DWORD prevOptions = SymGetOptions();
            SymSetOptions( prevOptions & (~SYMOPT_DEFERRED_LOADS) );
            DWORD64 loadedAddr = SymLoadModuleEx( s_DbgHelpSymHandle, nullptr, imageName, nullptr, moduleEntry->start, moduleEntry->end ? (moduleEntry->end - moduleEntry->start) : 0, nullptr, 0 );
            SymSetOptions( prevOptions );
            if( !SymGetModuleInfo64( s_DbgHelpSymHandle, moduleEntry->start, &moduleInfo ) )
            {
                return;
            }
        }

        if( moduleInfo.CVSig != CV_SIGNATURE_RSDS ) // Do we have a pdb ?
            return;

        ImageDebugInfo& debugInfo = moduleEntry->imageDebugInfo;
        debugInfo.debugFormat = ImageDebugFormatId::PdbDebugFormat;

        const uint32_t pdbFileNameLen = static_cast<uint32_t>( strlen( moduleInfo.CVData ) );
        debugInfo.debugDataSize = sizeof( PEImageDebugData ) + ( pdbFileNameLen + 1 );
        debugInfo.debugData = (uint8_t*)tracy_malloc( debugInfo.debugDataSize );
        PEImageDebugData* ptrToWindowsDebugData = reinterpret_cast<PEImageDebugData*>( debugInfo.debugData );
        ptrToWindowsDebugData->majorVersion = 0;
        ptrToWindowsDebugData->minorVersion = 0;
        ptrToWindowsDebugData->exeDataTimeStamp = moduleInfo.TimeDateStamp;

        PdbInfo* pdbInfo = &ptrToWindowsDebugData->cvInfo;

        pdbInfo->Age = moduleInfo.PdbAge;
        pdbInfo->CvSignature = moduleInfo.CVSig;

        static_assert( sizeof( pdbInfo->Signature ) == sizeof( moduleInfo.PdbSig70 ), "GUID size must match" );
        memcpy( &pdbInfo->Signature, &moduleInfo.PdbSig70, sizeof( moduleInfo.PdbSig70 ) );

        const GUID* guidd = reinterpret_cast<const GUID*>( &pdbInfo->Signature );

        char* pdbFileName = (char*)debugInfo.debugData + sizeof( PEImageDebugData );
        memcpy( pdbFileName, moduleInfo.CVData, pdbFileNameLen + 1 );
    }
}

ImageEntry* CacheModuleInfo( const char* imageName, uint32_t imageNameLength, uint64_t baseOfDll, uint32_t dllSize )
{
    ImageEntry moduleEntry = {};
    moduleEntry.start = baseOfDll;
    moduleEntry.end = baseOfDll + dllSize;
    moduleEntry.path = CopyStringFast( imageName, imageNameLength );
    FormatImageName( &moduleEntry.name, imageName, imageNameLength );

    ImageDebugFormatId debugFormat = ImageDebugFormatId::NoDebugFormat;
    uint8_t* debugData = nullptr;
    uint32_t debugDataSize = 0;

    if( GetModuleInfoFromPEHeaders( moduleEntry.start, &debugFormat, &debugData, &debugDataSize ) )
    {
        ImageDebugInfo& dmf = moduleEntry.imageDebugInfo;

        dmf.debugFormat = debugFormat;
        dmf.debugData = debugData;
        dmf.debugDataSize = debugDataSize;
    }

    std::lock_guard<std::recursive_mutex> mutexguard{ s_cacheMutex };
    return s_imageCache->CacheModuleWithDebugInfo( moduleEntry );
}

ImageEntry* LoadSymbolsForModuleAndCache( const char* imageName, uint32_t imageNameLength, uint64_t baseOfDll, uint32_t dllSize )
{
    assert( s_DbgHelpSymHandle == GetCurrentProcess() ); // Only resolve we path if resolving current process
    SymLoadModuleEx( s_DbgHelpSymHandle, nullptr, imageName, nullptr, baseOfDll, dllSize, nullptr, 0 );
    
    return CacheModuleInfo( imageName, imageNameLength, baseOfDll, dllSize );
}

struct ModuleNameAndBaseAddress
{
    const char* name;
    uint64_t baseAddr;
};

ModuleNameAndBaseAddress TryToLoadModuleDebugInfoAndCache( uint64_t address )
{
    InitRpmalloc();
    HMODULE mod[1024];
    DWORD needed;
    HANDLE proc = GetCurrentProcess();

    if( EnumProcessModules( proc, mod, sizeof( mod ), &needed ) != 0 )
    {
        const auto sz = needed / sizeof(HMODULE);
        for(size_t i=0; i<sz; i++ )
        {
            MODULEINFO info;
            if( GetModuleInformation( proc, mod[i], &info, sizeof( info ) ) != 0 )
            {
                const auto base = uint64_t(info.lpBaseOfDll);
                if ( address >= base && address < base + info.SizeOfImage )
                {
                    char name[1024];
                    const auto nameLength = GetModuleFileNameA( mod[i], name, 1024 );
                    if ( nameLength > 0 )
                    {
                        // since this is the first time we encounter this module, load its symbols (needed for modules loaded after SymInitialize)
                        ImageEntry* ImageEntry = LoadSymbolsForModuleAndCache( name, nameLength, (DWORD64)info.lpBaseOfDll, info.SizeOfImage );
                        return ModuleNameAndBaseAddress{ ImageEntry->name, ImageEntry->start };
                    }
                }
            }
        }
    }
    return { nullptr, 0 };
}

ModuleNameAndBaseAddress GetModuleNameAndPrepareSymbols( uint64_t addr, bool* failed )
{
    if ( IsKernelAddress( addr ) )
    {
        if ( s_krnlCache )
        {
            const ImageEntry* entry = s_krnlCache->FindEntryFromAddr( addr );
            if ( entry )
            {
                return ModuleNameAndBaseAddress{ entry->name, entry->start };
            }
        }
        return ModuleNameAndBaseAddress{ "<kernel>", addr };
    }

    const ImageEntry* entry = s_imageCache->FindEntryFromAddr( addr );

    if ( entry != nullptr )
        return ModuleNameAndBaseAddress{ entry->name, entry->start };


    *failed = true;
    return ModuleNameAndBaseAddress{ "[unknown]", addr };
}




void InitCallstackCritical()
{
    ___tracy_RtlWalkFrameChain = (___tracy_t_RtlWalkFrameChain)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlWalkFrameChain");
}

void DbgHelpInit( HANDLE symHandle, bool invadeProcess )
{
    assert(s_DbgHelpSymHandle == 0);
    s_DbgHelpSymHandle = symHandle;
    
    HMODULE DbgHelpHdl = GetModuleHandleA( "dbghelp.dll" );
    if ( !DbgHelpHdl ) {
        TracyDebug("Couldn't load DbgHelp.dll\n");
        return;
    }

    _SymAddrIncludeInlineTrace = (t_SymAddrIncludeInlineTrace)GetProcAddress( DbgHelpHdl, "SymAddrIncludeInlineTrace" );
    _SymQueryInlineTrace = (t_SymQueryInlineTrace)GetProcAddress( DbgHelpHdl, "SymQueryInlineTrace" );
    _SymFromInlineContext = (t_SymFromInlineContext)GetProcAddress( DbgHelpHdl, "SymFromInlineContext" );
    _SymGetLineFromInlineContext = (t_SymGetLineFromInlineContext)GetProcAddress( DbgHelpHdl, "SymGetLineFromInlineContext" );

#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_INIT;
    DBGHELP_LOCK;
#endif

    SymSetOptions(
        SYMOPT_LOAD_LINES
        | SYMOPT_UNDNAME // TODO: check if tracy doesn't rely on this to find decorated names in the dissassembler
        | SYMOPT_DEFERRED_LOADS
#ifndef NDEBUG
        | SYMOPT_DEBUG
#endif
    );

    if ( !SymInitialize( symHandle, nullptr, false ) )
    {
        TracyDebug( "Failed to initalize DbgHelp %x\n", GetLastError() );
    }

#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_UNLOCK;
#endif
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

        const auto sz = needed / sizeof(LPVOID);
        int cnt = 0;
        for( size_t i=0; i<sz; i++ )
        {
            char fn[MAX_PATH];
            const auto len = GetDeviceDriverBaseNameA( dev[i], fn, sizeof( fn ) );
            if( len != 0 )
            {
                auto buf = (char*)tracy_malloc_fast( len+3 );
                buf[0] = '<';
                memcpy( buf + 1, fn, len );
                memcpy( buf + len + 1, ">", 2 );
                ImageEntry kernelDriver{};

                kernelDriver.start = (uint64_t)dev[i];
                kernelDriver.end = 0;
                kernelDriver.name = buf;
                kernelDriver.path = nullptr;
                kernelDriver.imageDebugInfo = {};

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

                    kernelDriver.path = CopyStringFast( path );

                    if( SymLoadModuleEx( s_DbgHelpSymHandle, nullptr, path, nullptr, (DWORD64)dev[i], 0, nullptr, 0 ) )
                    {
                        // Kernel drivers PE headers are not accessible from userland, use DbgHelp to retrieve debug info.
                        GetModuleInfoFromDbgHelp( path, &kernelDriver );
                        // We no longer need it if we resolve symbols offline, unload it.
                        if( s_shouldResolveSymbolsOffline )
                        {
                            SymUnloadModule64( s_DbgHelpSymHandle, (DWORD64)dev[i] );
                        }
                    }
                }

                s_krnlCache->CacheModuleWithDebugInfo( kernelDriver );
                assert( kernelDriver.end == 0 && "kernel end should be zero" );
                cnt++;
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
    if( EnumProcessModules( proc, mod, sizeof(mod), &needed ) != 0 )
    {
        const auto sz = needed / sizeof(HMODULE);
        for( size_t i=0; i<sz; i++ )
        {
            MODULEINFO info;
            if( GetModuleInformation( proc, mod[i], &info, sizeof( info ) ) != 0)
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
        s_imageCache->Sort();
    }
}

void InitCallstack()
{
#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
    s_shouldResolveSymbolsOffline = GetEnvBool("TRACY_SYMBOL_OFFLINE_RESOLVE", s_shouldResolveSymbolsOffline);
#endif //#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
    if (s_shouldResolveSymbolsOffline)
    {
        TracyDebug("TRACY: enabling offline symbol resolving!\n");
    }

#ifdef TRACY_ENABLE // Client or self-profiling server
    // Use GetCurrentProcess() as this is used by default in most apps, but we should probably be using a fake handle to avoid collisions?
    DbgHelpInit(GetCurrentProcess(), true /*Invade process, even though it should be unnecessary since we'll preload all modules and drivers*/);
#else
    DbgHelpInit((HANDLE)42/*This is our fake DbgHelp Handle*/, false /* Don't invade the process, we're going to resolve symbols for another one*/);
#endif

    CreateImageCaches();
    
#ifdef TRACY_ENABLE // Client or self-profiling server
#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_LOCK;
#endif
    // use TRACY_NO_DBGHELP_INIT_LOAD=1 to disable preloading of driver
    // and process module symbol loading at startup time - they will be loaded on demand later
    // Sometimes this process can take a very long time and prevent resolving callstack frames
    // symbols during that time.
    const char* noInitLoadEnv = GetEnvVar("TRACY_NO_DBGHELP_INIT_LOAD");
    const bool initTimeModuleLoad = !(noInitLoadEnv && noInitLoadEnv[0] == '1');
    if ( !initTimeModuleLoad )
    {
        TracyDebug("TRACY: skipping init time dbghelper module load\n");
    }
    
    std::lock_guard<std::recursive_mutex> mutexguard{ s_cacheMutex };

    if ( initTimeModuleLoad )
    {
        CacheProcessDrivers();
        CacheProcessModules();
    }

#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_UNLOCK;
#endif
#endif
}

void EndCallstack()
{
    DestroyImageCaches();
    if ( s_DbgHelpSymHandle )
    {
        SymCleanup(s_DbgHelpSymHandle);
        s_DbgHelpSymHandle = 0;
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
    assert( addr >> 63 != 0 );
    if( !s_krnlCache ) return nullptr;

    const ImageEntry* imageEntry = s_krnlCache->FindEntryFromAddr( addr );
    if( imageEntry ) return imageEntry->path;
    return nullptr;
}

bool LoadFromPdb( const char* moduleName, uint64_t baseAddress, uint64_t dllSize, ImageDebugFormatId debugFormat, const uint8_t* debugData, uint32_t debugDataSize )
{
    assert( debugFormat == ImageDebugFormatId::PdbDebugFormat );

    const uint32_t DataForDebugSize = static_cast<const uint32_t>( debugDataSize );
    assert( moduleName != nullptr );

    const tracy::PEImageDebugData* windowsDebugData = (const tracy::PEImageDebugData*)( debugData );
    const size_t pdbPathLength = debugDataSize - sizeof( tracy::PEImageDebugData );
    const uint8_t* pdbPath = debugData + sizeof( tracy::PEImageDebugData );

    static_assert( sizeof( PEImageDebugData ) == 32, "Structure changed or not properly packed" );

    static_assert( offsetof( CV_INFO_PDB70, CvSignature ) == offsetof( PdbInfo, CvSignature ), "Mismatch with DbgHelp headers." );
    static_assert( offsetof( CV_INFO_PDB70, Signature ) == offsetof( PdbInfo, Signature ), "Mismatch with DbgHelp headers." );
    static_assert( offsetof( CV_INFO_PDB70, Age ) == offsetof( PdbInfo, Age ), "Mismatch with DbgHelp headers." );
    static_assert( offsetof( CV_INFO_PDB70, PdbFileName ) == sizeof( PdbInfo ), "Mismatch with DbgHelp headers." );

    const uint32_t sizeOfPdbData = DataForDebugSize - offsetof( PEImageDebugData, cvInfo );

    static constexpr auto mandatoryAlignment = 8;

    auto const debug_module_info_size = sizeof( IMAGE_DEBUG_DIRECTORY ) + sizeOfPdbData;
    auto const debug_module_info_size_aligned = ( debug_module_info_size + mandatoryAlignment ) & ( ~uint64_t( mandatoryAlignment - 1 ) );

    uint8_t* dataBuffer = static_cast<uint8_t*>( tracy_malloc( debug_module_info_size_aligned ) );
    IMAGE_DEBUG_DIRECTORY* info = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>( dataBuffer );

    info->TimeDateStamp = windowsDebugData->exeDataTimeStamp;
    info->Characteristics = 0;
    info->MajorVersion = windowsDebugData->majorVersion;
    info->MinorVersion = windowsDebugData->minorVersion;
    info->Type = IMAGE_DEBUG_TYPE_CODEVIEW;
    info->AddressOfRawData = 0;
    info->PointerToRawData = sizeof( IMAGE_DEBUG_DIRECTORY );
    info->SizeOfData = sizeOfPdbData;

    memcpy( dataBuffer + info->PointerToRawData, &windowsDebugData->cvInfo, sizeOfPdbData );

    MODLOAD_DATA module_load_info;
    module_load_info.ssize = sizeof( module_load_info );
    module_load_info.ssig = DBHHEADER_DEBUGDIRS;
    module_load_info.data = dataBuffer;
    module_load_info.size = static_cast<DWORD>( debug_module_info_size_aligned );
    module_load_info.flags = 0;

    DWORD64 loaddedModule = SymLoadModuleEx( s_DbgHelpSymHandle, NULL, moduleName, NULL, baseAddress,
        dllSize, &module_load_info, 0 );

    tracy_free( dataBuffer );


    IMAGEHLP_MODULEW64 moduleInfoDebug{};
    moduleInfoDebug.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
    if( SymGetModuleInfoW64( s_DbgHelpSymHandle, loaddedModule, &moduleInfoDebug ) == TRUE )
    {
        // Consider deferred to be failing too as it may fail later. We might want to handle failure in the UI.
        if( moduleInfoDebug.SymType != SymNone && moduleInfoDebug.SymType != SymDeferred )
        {
            return true;
        }
    }
    return false;
}

// Called from the profiler (server) only, we received data from the client.
void CacheImageAndLoadDebugInfo( ImageEntry& imageEntry, bool loadDebugInfo )
{
    if ( IsKernelAddress( imageEntry.start ) )
    {
        s_krnlCache->CacheModuleWithDebugInfo( imageEntry );
    }
    else
    {
        s_imageCache->CacheModuleWithDebugInfo( imageEntry );
    }

    bool hasSymbolInfo = false;
    if( imageEntry.imageDebugInfo.debugFormat == ImageDebugFormatId::PdbDebugFormat )
    {
        char* nameFixed = nullptr;
        if( IsKernelAddress( imageEntry.start ) )
        {
            const size_t nameLen = strlen( imageEntry.name );
            if( nameLen > 3 && imageEntry.name[0] == '<' && imageEntry.name[nameLen - 1] == '>' )
            {
                char* kernelName = CopyStringFast( imageEntry.name + 1 );
                kernelName[nameLen - 2] = 0; // replace >
                nameFixed = kernelName;
            }
        }
        hasSymbolInfo = LoadFromPdb( nameFixed ? nameFixed : imageEntry.name, imageEntry.start, imageEntry.end ? (imageEntry.end - imageEntry.start) : 0,
            imageEntry.imageDebugInfo.debugFormat, imageEntry.imageDebugInfo.debugData, imageEntry.imageDebugInfo.debugDataSize );

        if( nameFixed ) tracy_free_fast( nameFixed );
    }

    if ( !hasSymbolInfo )
    {
        // TODO: load from path only if we can check we got the correct binary (check timestamp / guid ?)
        //       That would however require to disable deferred symbol loading or use FindExecutableImageEx
        // SymLoadModuleEx(s_DbgHelpSymHandle, nullptr, imageEntry.name, nullptr, baseOfDll, dllSize, nullptr, 0);
    }
   
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
    line.SizeOfStruct = sizeof( IMAGEHLP_LINE64 );
#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_LOCK;
#endif
    const auto res = SymGetLineFromAddr64( s_DbgHelpSymHandle, ptr, &displacement, &line );
    if ( res == 0 || line.LineNumber >= 0xF00000 )
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

CallstackEntryData DecodeCallstackPtr( uint64_t ptr, DecodeCallStackPtrStatus* _decodeCallStackPtrStatus )
{
#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_LOCK;
#endif

    InitRpmalloc();

    bool moduleNotFound = false;
    ModuleNameAndBaseAddress moduleNameAndAddress = GetModuleNameAndPrepareSymbols( ptr, &moduleNotFound );
    
    *_decodeCallStackPtrStatus = DecodeCallStackPtrStatusFlags::Success;

    if( moduleNotFound )
    {
        if( s_DbgHelpSymHandle == GetCurrentProcess() )
        {
            // We're on the client or self profiling, try to load a potentially new module.
            moduleNameAndAddress = TryToLoadModuleDebugInfoAndCache( ptr );
            if (moduleNameAndAddress.baseAddr == 0)
            {
                // Failed to find the module information.
                // Set base address to ptr so that cb_data[0].symAddr=0
                moduleNameAndAddress = { "[unknown]", ptr };
            }
            else {
                *_decodeCallStackPtrStatus |= DecodeCallStackPtrStatusFlags::NewModuleFound;
                moduleNotFound = false; // We managed to load the module information
            }
        }
        else
        {
            // We're on the server, it does not have a way to get information about the module
            *_decodeCallStackPtrStatus |= DecodeCallStackPtrStatusFlags::ModuleMissing;
        }
    }

    if( s_shouldResolveSymbolsOffline || moduleNotFound )
    {
#ifdef TRACY_DBGHELP_LOCK
        DBGHELP_UNLOCK;
#endif
        
        cb_data[0].symAddr = ptr - moduleNameAndAddress.baseAddr;
        cb_data[0].symLen = 0;

        cb_data[0].name = CopyStringFast("[unresolved]");
        cb_data[0].file = CopyStringFast("[unknown]");
        cb_data[0].line = 0;

        return { cb_data, 1, moduleNameAndAddress.name };
    }

    int write;
    const auto proc = s_DbgHelpSymHandle;

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
    if( !symValid ) {
        *_decodeCallStackPtrStatus |= DecodeCallStackPtrStatusFlags::SymbolMissing;
#ifdef TRACY_VERBOSE
        static bool doOnce = true;
        if(doOnce)
        {
            if( GetModuleHandleA( "symsrv.dll" ) == NULL )
            {
                TracyDebug( "symsrv.dll was not loaded. Symbol resolution may fail.\n" );
            }
            doOnce = false;
        }
#endif
    }


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


    return { cb_data, uint8_t(cb_num), moduleNameAndAddress.name };
}

#elif defined(TRACY_USE_LIBBACKTRACE)

enum { MaxCbTrace = 64 };

struct backtrace_state* cb_bts = nullptr;

int cb_num;
CallstackEntry cb_data[MaxCbTrace];
int cb_fixup;

void CacheImageAndLoadDebugInfo( ImageEntry& imageEntry, bool loadDebugInfo ) {}

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

static void InitKernelSymbols()
{
    if ( s_krnlSymbolsCache == nullptr )
    {
        s_krnlSymbolsCache = new( tracy_malloc( sizeof( ImageCache ) ) ) ImageCache();
    }

    FILE* f = fopen( "/proc/kallsyms", "rb" );
    if( !f ) return;
    tracy::FastVector<ImageEntry> tmpSym( 512 * 1024 );
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

            strname = (char*)tracy_malloc_fast( nameend - namestart + 1 );
            memcpy( strname, namestart, nameend - namestart );
            strname[nameend-namestart] = '\0';

            if( modstart )
            {
                strmod = (char*)tracy_malloc_fast( modend - modstart + 1 );
                memcpy( strmod, modstart, modend - modstart );
                strmod[modend-modstart] = '\0';
            }
        }

        // Note: This uses the image cache as a symbol cache.
        ImageEntry kernelSymbol{};
        kernelSymbol.start = addr;
        kernelSymbol.end = 0;
        kernelSymbol.name = strname;
        kernelSymbol.path = strmod;

        s_krnlSymbolsCache->CacheModuleWithDebugInfo( kernelSymbol );

    }
    tracy_free_fast( linebuf );
    fclose( f );

    s_krnlSymbolsCache->Sort();

    TracyDebug( "Loaded %zu kernel symbols (%zu code sections)\n", tmpSym.size(), validCnt );
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

#ifdef TRACY_USE_IMAGE_CACHE
    CreateImageCaches();
#endif //#ifdef TRACY_USE_IMAGE_CACHE

#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
    s_shouldResolveSymbolsOffline = GetEnvBool( "TRACY_SYMBOL_OFFLINE_RESOLVE", s_shouldResolveSymbolsOffline );
#endif //#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
    if( s_shouldResolveSymbolsOffline )
    {
        cb_bts = nullptr; // disable use of libbacktrace calls
        TracyDebug("TRACY: enabling offline symbol resolving!\n");
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
    TracyDebug( "DebugInfo descriptor query: %i, fn: %s\n", fd, filename );
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
#ifdef TRACY_USE_IMAGE_CACHE
    DestroyImageCaches();
#endif //#ifdef TRACY_USE_IMAGE_CACHE
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

CallstackSymbolData DecodeSymbolAddress( uint64_t ptr )
{
    CallstackSymbolData sym;
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

CallstackEntryData DecodeCallstackPtr( uint64_t ptr, DecodeCallStackPtrStatus* _decodeCallStackPtrStatus )
{
    InitRpmalloc();

#ifdef TRACY_ENABLE // Only works on the current process. Profiler does not have TRACY_ENABLE, or is self profiling

    if( ptr >> 63 == 0 )
    {
        const char* imageName = nullptr;
        uint64_t imageBaseAddress = 0x0;

#ifdef TRACY_USE_IMAGE_CACHE
        const auto* image = s_imageCache->GetImageForAddress(ptr);
        if( image )
        {
            imageName = image->name;
            imageBaseAddress = uint64_t(image->start);
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

        if ( imageName )
        {
            *_decodeCallStackPtrStatus = DecodeCallStackPtrStatusFlags::Success;

        }
        else 
        {
        
            *_decodeCallStackPtrStatus |= DecodeCallStackPtrStatusFlags::SymbolMissing;
        }
        return { cb_data, uint8_t( cb_num ), imageName ? imageName : "[unknown]" };
    }
#ifdef __linux
    else if( s_krnlSymbolsCache )
    {
        // This is a symbol cache, kernel image cache is currently unused
        const ImageEntry* symbolEntry = s_krnlSymbolsCache->FindEntryFromAddr((uint64_t)ptr);
        if ( symbolEntry )
        {
            cb_data[0].name = CopyStringFast( symbolEntry->name );
            cb_data[0].file = CopyStringFast( "<kernel>" );
            cb_data[0].line = 0;
            cb_data[0].symLen = symbolEntry->end - symbolEntry->start;
            cb_data[0].symAddr = symbolEntry->start;
            *_decodeCallStackPtrStatus = DecodeCallStackPtrStatusFlags::Success;
            return { cb_data, 1, symbolEntry->path ? symbolEntry->path : "<kernel>" };
        }
    }
#endif
#endif
    cb_data[0].name = CopyStringFast( "[unknown]" );
    cb_data[0].file = CopyStringFast( "<kernel>" );
    cb_data[0].line = 0;
    cb_data[0].symLen = 0;
    cb_data[0].symAddr = 0;
    *_decodeCallStackPtrStatus = DecodeCallStackPtrStatusFlags::Success;
    return { cb_data, 1, "<kernel>" };
}

#elif TRACY_HAS_CALLSTACK == 5

void CacheImageAndLoadDebugInfo( ImageEntry& imageEntry, bool loadDebugInfo ) {}

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

CallstackEntryData DecodeCallstackPtr( uint64_t ptr, DecodeCallStackPtrStatus* _decodeCallStackPtrStatus )
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

    *_decodeCallStackPtrStatus = DecodeCallStackPtrStatus::Success;
    return { &cb, 1, symloc };
}

#endif

}

#endif
