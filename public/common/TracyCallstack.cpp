#include <limits>
#include <new>
#include <stdio.h>
#include <string.h> // for memcpy
#include <assert.h>

#include "TracyCallstack.hpp"
#include "TracyDebug.hpp"
#include "TracyStringHelpers.hpp"
#include "TracyAlloc.hpp"
#include "TracySystem.hpp"
#include "TracyDebugModulesHeaderFile.hpp"



#    pragma optimize( "", off )






#ifdef TRACY_HAS_CALLSTACK

constexpr uint32_t ImageCacheBaseCapacity = 512;

#define CLIENT_SEND_IMAGES_INFO "CLIENT_SEND_IMAGES_INFO"
#define SERVER_LOCAL_RESOLVE "SERVER_LOCAL_RESOLVE"


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
#  ifdef _MSC_VER
#    pragma warning( pop )
#  endif
#elif TRACY_HAS_CALLSTACK == 2 || TRACY_HAS_CALLSTACK == 3 || TRACY_HAS_CALLSTACK == 4 || TRACY_HAS_CALLSTACK == 6
#  include "../libbacktrace/backtrace.hpp"
#  include <algorithm>
#  include <dlfcn.h>
#  include <cxxabi.h>
#  include <stdlib.h>
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

//#define TRACY_USE_IMAGE_CACHE

namespace tracy 
{
    // when "TRACY_SYMBOL_OFFLINE_RESOLVE" is set, instead of fully resolving symbols at runtime,
// simply resolve the offset and image name (which will be enough the resolving to be done offline)
#ifdef TRACY_SYMBOL_OFFLINE_RESOLVE
    constexpr bool s_shouldResolveSymbolsOffline = true;
#else
    static bool s_shouldResolveSymbolsOffline = false;

    static bool s_clientSendImageInfo = false;
    static bool s_serverLocalResolve = false; // Should the profiler try to resolve symbols before querying the client for symbols.

    inline bool IsEnv(const char* environementVariableName)
    {
        const char* v = GetEnvVar(environementVariableName);

        return (v && v[0] == '1');
    }

    struct ModuleNameAndBaseAddress
    {
        const char* name;
        uint64_t baseAddr;
    };

    // The only threads that access the cache are the Symbol Worker and the Tracy Thread
    // Only the symbol worker may write, but the Tracy Thread needs to be able to read the cache safely
    // Since only the SymbolWorker is allowed to write the cache, it does not need to lock when reading.
    static std::recursive_mutex s_cacheMutex;
    std::recursive_mutex& GetModuleCacheMutexForRead() {
        return s_cacheMutex;
    }

    void DestroyModuleCacheEntry(ModuleCacheEntry& entry)
    {
        tracy_free_fast(entry.path);
        entry.path = nullptr;
        tracy_free_fast(entry.name);
        entry.name = nullptr;
        tracy_free(entry.degugModuleField.debugData);
        entry.degugModuleField.debugData = nullptr;
    }

    class ImageCache
    {
    public:
        const ModuleCacheEntry* FindEntryFromAddr(uint64_t addr) const
        {
            for (size_t i = 0; i < m_modCache.size(); i++)
            {
                auto& it = m_modCache[i];

                if (addr >= it.start && addr < it.end)
                    return &it;

            }

            auto it = std::lower_bound(m_modCache.begin(), m_modCache.end(), addr, [](const ModuleCacheEntry& lhs, const uint64_t& rhs) { return lhs.start > rhs; });
            if (it != m_modCache.end() && (addr < it->end))
                return &(*it);

            return nullptr;
        }


        void MapModuleData(const ModuleCacheEntry** moduleCacheEntries, size_t* moduleCount)
        {
            if (!s_clientSendImageInfo && m_modCache.empty())
            {
                *moduleCacheEntries = nullptr;
                *moduleCount = 0;
                return;
            }

            *moduleCacheEntries = m_modCache.data();
            *moduleCount = m_modCache.size();
        }

        ModuleCacheEntry* CacheModuleWithDebugInfo(const ModuleCacheEntry& entry)
        {
            ModuleCacheEntry* newEntry = m_modCache.push_next();
            *newEntry = entry;
            return newEntry;
        }

        void Clear()
        {
            for (ModuleCacheEntry& cacheEntry : m_modCache)
            {
                DestroyModuleCacheEntry(cacheEntry);
            }
            m_modCache.clear();
        }

        bool Contain(const ModuleCacheEntry& moduleCacheEntry)
        {
            return std::find_if(m_modCache.begin(), m_modCache.end(), [moduleCacheEntry](const ModuleCacheEntry& module)->bool
                {
                    return moduleCacheEntry.start == moduleCacheEntry.start;
                }) != m_modCache.end();
        }

        const FastVector<ModuleCacheEntry>& GetModuleData() const 
        {
            return m_modCache;
        }

        ImageCache(size_t moduleCacheCapacity) : m_modCache(moduleCacheCapacity)
        {

        }


        ~ImageCache()
        {
            Clear();
        }


    protected:
        FastVector<ModuleCacheEntry> m_modCache;

    };
}


#if TRACY_HAS_CALLSTACK == 2 || TRACY_HAS_CALLSTACK == 3 || TRACY_HAS_CALLSTACK == 4 || TRACY_HAS_CALLSTACK == 5 || TRACY_HAS_CALLSTACK == 6
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

#if TRACY_HAS_CALLSTACK == 3
#   define TRACY_USE_IMAGE_CACHE
#   include <link.h>
#endif

namespace tracy
{

#ifdef TRACY_USE_IMAGE_CACHE
// when we have access to dl_iterate_phdr(), we can build a cache of address ranges to image paths
// so we can quickly determine which image an address falls into.
// We refresh this cache only when we hit an address that doesn't fall into any known range.
class ImageCacheLinux : public ImageCache
{
public:
    ImageCacheLinux()
        : ImageCache(ImageCacheAllocSize)
    {
        // ??
        Refresh();
    }

    ~ImageCacheLinux()
    {
        m_haveMainImageName = false;
    }

    const ModuleCacheEntry* GetImageForAddress( void* address )
    {
        const ModuleCacheEntry* entry = FindEntryFromAddr( (uint64_t)address );

        /*if (!entry)
        {
            Refresh();
            return GetImageForAddressImpl( address );
        }*/
        return entry;
    }

private:
    bool m_updated = false;
    bool m_haveMainImageName = false;

    bool Contains(void* startAddress) const
    {
        uint64_t address = (uint64_t)startAddress;
        return std::any_of(m_modCache.begin(), m_modCache.end(), [address](const ModuleCacheEntry& entry) { return address == entry.start; });
    }

    static int Callback( struct dl_phdr_info* info, size_t size, void* data )
    {
        // SCARY
        ImageCacheLinux* cache = reinterpret_cast<ImageCacheLinux*>( data );

        const auto startAddress = reinterpret_cast<void*>( info->dlpi_addr );
        if( cache->Contains( startAddress ) ) return 0;

        const uint32_t headerCount = info->dlpi_phnum;
        assert( headerCount > 0);
        const auto endAddress = reinterpret_cast<void*>( info->dlpi_addr +
            info->dlpi_phdr[info->dlpi_phnum - 1].p_vaddr + info->dlpi_phdr[info->dlpi_phnum - 1].p_memsz);

        ImageEntry* image = cache->m_images.push_next();
        image->m_startAddress = startAddress;
        image->m_endAddress = endAddress;

        // the base executable name isn't provided when iterating with dl_iterate_phdr,
        // we will have to patch the executable image name outside this callback
        if( info->dlpi_name && info->dlpi_name[0] != '\0' )
        {
            size_t sz = strlen( info->dlpi_name ) + 1;
            image->m_name = (char*)tracy_malloc( sz );
            memcpy( image->m_name,  info->dlpi_name, sz );
        }
        else
        {
            image->m_name = nullptr;
        }

        cache->m_updated = true;

        return 0;
    }

 

    void Refresh()
    {
        m_updated = false;
        dl_iterate_phdr( Callback, this );

        if( m_updated )
        {
            std::sort( m_modCache.begin(), m_modCache.end(),
                []( const ModuleCacheEntry& lhs, const ModuleCacheEntry& rhs ) { return lhs.start > rhs.start; } );

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

        for(ModuleCacheEntry& entry : m_modCache)
        {
            if( entry.name == nullptr )
            {
                Dl_info dlInfo;
                if( dladdr( (void *)entry.start, &dlInfo ) )
                {
                    if( dlInfo.dli_fname )
                    {
                        size_t sz = strlen( dlInfo.dli_fname ) + 1;
                        entry.name = (char*)tracy_malloc( sz );
                        memcpy( entry.name, dlInfo.dli_fname, sz );
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
        for( ImageEntry& entry : m_images )
        {
            tracy_free( entry.m_name );
        }

        m_images.clear();
        m_haveMainImageName = false;
    }
};
#endif //#ifdef TRACY_USE_IMAGE_CACHE





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

bool ShouldResolveSymbolsOffline()
{
    return IsEnv("TRACY_SYMBOL_OFFLINE_RESOLVE");
}
#endif // #ifdef TRACY_SYMBOL_OFFLINE_RESOLVE

#if TRACY_HAS_CALLSTACK == 1

enum { MaxCbTrace = 64 };
enum { MaxNameSize = 8*1024 };

int cb_num;
CallstackEntry cb_data[MaxCbTrace];

HANDLE s_DbgHelpSymHandle = 0;
#pragma comment( lib, "dbghelp.lib" )

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

static constexpr auto mandatoryAlignment = 8;
static constexpr DWORD CV_SIGNATURE_RSDS = 'SDSR'; // 'SDSR'



FastVector<ModuleCacheEntry>* s_krnlCache = nullptr;



ImageCache* s_imageCacheWindows = nullptr;

uint64_t DbgHelpLoadSymbolsForModule(const char* imageName, uint64_t baseOfDll, uint32_t dllSize)
{
    auto d = SymLoadModuleEx(s_DbgHelpSymHandle, nullptr, imageName, nullptr, baseOfDll, dllSize, nullptr, 0);

    IMAGEHLP_MODULEW64 moduleInfo{};
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
    if (TRUE == SymGetModuleInfoW64(s_DbgHelpSymHandle, (uintptr_t)baseOfDll, &moduleInfo))
    {
        wprintf(L"- ImageName=%s\n", moduleInfo.ImageName);
        wprintf(L"- LoadedPdbName=%s\n", moduleInfo.LoadedPdbName);
    }

    return d;
}


bool GetModulePDBData(uint64_t baseOfDll, DebugFormat* debugFormat, uint8_t** debugInformationData, uint32_t* debugInformationSize)
{
    if (!s_clientSendImageInfo)
        return false;

    static constexpr bool MappedAsImage = true;

    PVOID BaseAddress = (void*)baseOfDll;

    PIMAGE_NT_HEADERS header = ImageNtHeader(BaseAddress);

    ULONG debugDirectoryCount = 0;
    IMAGE_SECTION_HEADER* debugSectionHeader;

    PVOID debugSectionData = ImageDirectoryEntryToDataEx(BaseAddress, true, IMAGE_DIRECTORY_ENTRY_DEBUG,
        &debugDirectoryCount, &debugSectionHeader);

    if (debugSectionData == NULL)
    {
        return false;
    }
    IMAGE_DEBUG_DIRECTORY* debugDirectory = static_cast<IMAGE_DEBUG_DIRECTORY*>(debugSectionData);

    for (size_t i = 0; (i * sizeof(IMAGE_DEBUG_DIRECTORY)) < debugDirectoryCount; i++)
    {

        const IMAGE_DEBUG_DIRECTORY& curDebugDirectory = debugDirectory[i];

        if (debugDirectory[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;

        CV_INFO_PDB70* pData = (CV_INFO_PDB70*)(uintptr_t(BaseAddress) + 
            (MappedAsImage 
            ? debugDirectory[i].AddressOfRawData
            : debugDirectory[i].PointerToRawData)
            );

        if (pData->CvSignature != CV_SIGNATURE_RSDS) continue;

        *debugFormat = DebugFormat::PdbDebugFormat;

        const uint32_t pdbFileLength = strlen((const char*)pData->PdbFileName);
        const uint32_t debugFormatSize = sizeof(WindowsDebugData) + pdbFileLength + 1;
        *debugInformationData = (uint8_t*)tracy_malloc(debugFormatSize);
        *debugInformationSize = debugFormatSize;

        uint8_t* ptrToDebugPacket = reinterpret_cast<uint8_t*>(*debugInformationData);
        WindowsDebugData* ptrToWindowsDebugData = reinterpret_cast<WindowsDebugData*>(ptrToDebugPacket);

        // write minor major version
        ptrToWindowsDebugData->majorVersion = curDebugDirectory.MajorVersion;
        ptrToWindowsDebugData->minorVersion = curDebugDirectory.MinorVersion;

        ptrToWindowsDebugData->exeDataTimeStamp = curDebugDirectory.TimeDateStamp;
        ptrToWindowsDebugData->cvInfo.Age = pData->Age;
        ptrToWindowsDebugData->cvInfo.CvSignature = pData->CvSignature;
        static_assert(sizeof(GUID) == sizeof(pData->Signature), "GUID size must match");
        memcpy(&ptrToWindowsDebugData->cvInfo.Signature, &pData->Signature, sizeof(pData->Signature));

        memcpy(ptrToDebugPacket + sizeof(WindowsDebugData), pData->PdbFileName, pdbFileLength + 1);

        return true;
    }
    return false;
}

ModuleCacheEntry* CacheModuleInfo(const char* imageName, uint32_t imageNameLength, uint64_t baseOfDll, uint32_t dllSize)
{

    ModuleCacheEntry moduleEntry = {};
    moduleEntry.start = baseOfDll;
    moduleEntry.end = baseOfDll + dllSize;
    moduleEntry.path = CopyStringFast(imageName, imageNameLength);
    FormatImageName(&moduleEntry.name, imageName, imageNameLength);

    DebugFormat debugFormat = DebugFormat::NoDebugFormat;
    uint8_t* debugData = nullptr;
    uint32_t debugDataSize = 0;

    if (GetModulePDBData(moduleEntry.start, &debugFormat, &debugData, &debugDataSize))
    {
        DegugModuleField& dmf = moduleEntry.degugModuleField;

        dmf.debugFormat = debugFormat;
        dmf.debugData = debugData;
        dmf.debugDataSize = debugDataSize;
    }

    std::lock_guard<std::recursive_mutex> mutexguard{ s_cacheMutex };
    return s_imageCacheWindows->CacheModuleWithDebugInfo(moduleEntry);
}

ModuleCacheEntry* LoadSymbolsForModuleAndCache(const char* imageName, uint32_t imageNameLength, uint64_t baseOfDll, uint32_t dllSize)
{
    DbgHelpLoadSymbolsForModule(imageName, baseOfDll, dllSize);
 
    return CacheModuleInfo(imageName, imageNameLength, baseOfDll, dllSize);
}

void GetModuleInfoFromDbgHelp(const char* imageName, ModuleCacheEntry* moduleEntry)
{
    IMAGEHLP_MODULE64 moduleInfo{};
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
    if (TRUE == SymGetModuleInfo64(s_DbgHelpSymHandle, moduleEntry->start, &moduleInfo))
    {
        if (moduleInfo.SymType == SymDeferred) // If symbol loading was deferred, force load it so that we can retrieve the debug informations
        {
            DWORD prevOptions = SymGetOptions();
            SymSetOptions(prevOptions & (~SYMOPT_DEFERRED_LOADS));
            DWORD64 loadedAddr = SymLoadModuleEx(s_DbgHelpSymHandle, nullptr, imageName, nullptr, moduleEntry->start, moduleEntry->end ? (moduleEntry->end - moduleEntry->start) : 0, nullptr, 0);
            SymSetOptions(prevOptions);
            if(!SymGetModuleInfo64(s_DbgHelpSymHandle, moduleEntry->start, &moduleInfo))
            {
                return;
            }
        }

        if (moduleInfo.CVSig != CV_SIGNATURE_RSDS) // Do we have a pdb ?
            return;

        DegugModuleField& debugInfo = moduleEntry->degugModuleField;
        debugInfo.debugFormat = DebugFormat::PdbDebugFormat;

        const uint32_t pdbFileNameLen = static_cast<uint32_t>(strlen(moduleInfo.CVData));
        debugInfo.debugDataSize = sizeof(WindowsDebugData) + (pdbFileNameLen + 1);
        debugInfo.debugData = (uint8_t*)tracy_malloc(debugInfo.debugDataSize);
        WindowsDebugData* ptrToWindowsDebugData = reinterpret_cast<WindowsDebugData*>(debugInfo.debugData);
        ptrToWindowsDebugData->majorVersion = 0;
        ptrToWindowsDebugData->minorVersion = 0;
        ptrToWindowsDebugData->exeDataTimeStamp = moduleInfo.TimeDateStamp;

        TracyPdbInfo* pdbInfo = &ptrToWindowsDebugData->cvInfo;

        pdbInfo->Age = moduleInfo.PdbAge;
        pdbInfo->CvSignature = moduleInfo.CVSig;

        static_assert(sizeof(pdbInfo->Signature) == sizeof(moduleInfo.PdbSig70), "GUID size must match");
        memcpy(&pdbInfo->Signature, &moduleInfo.PdbSig70, sizeof(moduleInfo.PdbSig70));

        const GUID* guidd = reinterpret_cast<const GUID*>(&pdbInfo->Signature);

        char* pdbFileName = (char*)debugInfo.debugData + sizeof(WindowsDebugData);
        memcpy(pdbFileName, moduleInfo.CVData, pdbFileNameLen + 1);
    }
}


ModuleNameAndBaseAddress OnFailedFindAddress(uint64_t address)
{
    InitRpmalloc();
    HMODULE mod[1024];
    DWORD needed;
    HANDLE proc = GetCurrentProcess();

    if (EnumProcessModules(proc, mod, sizeof(mod), &needed) != 0)
    {
        const auto sz = needed / sizeof(HMODULE);
        for (size_t i = 0; i < sz; i++)
        {
            MODULEINFO info;
            if (GetModuleInformation(proc, mod[i], &info, sizeof(info)) != 0)
            {
                const auto base = uint64_t(info.lpBaseOfDll);
                if (address >= base && address < base + info.SizeOfImage)
                {
                    char name[1024];
                    const auto nameLength = GetModuleFileNameA(mod[i], name, 1024);
                    if (nameLength > 0)
                    {
                        // since this is the first time we encounter this module, load its symbols (needed for modules loaded after SymInitialize)
                        ModuleCacheEntry* moduleCacheEntry = LoadSymbolsForModuleAndCache(name, nameLength, (DWORD64)info.lpBaseOfDll, info.SizeOfImage);
                        return ModuleNameAndBaseAddress{ moduleCacheEntry->name, moduleCacheEntry->start };
                    }
                }
            }
        }
    }
    return ModuleNameAndBaseAddress{ "[unknown]", address };
}

ModuleNameAndBaseAddress GetModuleNameAndPrepareSymbols(uint64_t addr, bool* failed)
{
    if ((addr >> 63) != 0)
    {
        if (s_krnlCache)
        {
            auto it = std::lower_bound(s_krnlCache->begin(), s_krnlCache->end(), addr, [](const ModuleCacheEntry& lhs, const uint64_t& rhs) { return lhs.start > rhs; });
            if (it != s_krnlCache->end())
            {
                return ModuleNameAndBaseAddress{ it->name, it->start };
            }
        }
        return ModuleNameAndBaseAddress{ "<kernel>", addr };
    }

    const ModuleCacheEntry* entry = s_imageCacheWindows->FindEntryFromAddr(addr);

    if (entry != nullptr)
        return ModuleNameAndBaseAddress{ entry->name, entry->start };


    if (s_serverLocalResolve)
    {
        *failed = true;
        return ModuleNameAndBaseAddress{ "[unknown]", addr };
    }

   return OnFailedFindAddress(addr);
}




void InitCallstackCritical()
{
    ___tracy_RtlWalkFrameChain = (___tracy_t_RtlWalkFrameChain)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlWalkFrameChain");
}

void DbgHelpInit(HANDLE symHandle, bool invadeProcess)
{
    assert(s_DbgHelpSymHandle == 0);
    s_DbgHelpSymHandle = symHandle;
    
    HMODULE DbgHelpHdl = GetModuleHandleA("dbghelp.dll");
    if (!DbgHelpHdl) {
        TracyDebug("Couldn't load DbgHelp.dll\n");
        return;
    }

    _SymAddrIncludeInlineTrace = (t_SymAddrIncludeInlineTrace)GetProcAddress(DbgHelpHdl, "SymAddrIncludeInlineTrace");
    _SymQueryInlineTrace = (t_SymQueryInlineTrace)GetProcAddress(DbgHelpHdl, "SymQueryInlineTrace");
    _SymFromInlineContext = (t_SymFromInlineContext)GetProcAddress(DbgHelpHdl, "SymFromInlineContext");
    _SymGetLineFromInlineContext = (t_SymGetLineFromInlineContext)GetProcAddress(DbgHelpHdl, "SymGetLineFromInlineContext");

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

    if (!SymInitialize(symHandle, nullptr, false))
    {
        TracyDebug("Failed to initalize DbgHelp %x\n", GetLastError());
    }

#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_UNLOCK;
#endif
}


static void CacheProcessDrivers()
{
    DWORD needed;
    LPVOID dev[4096];
    if (EnumDeviceDrivers(dev, sizeof(dev), &needed) != 0)
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
                memcpy(buf + 1, fn, len);
                memcpy(buf + len + 1, ">", 2);
                ModuleCacheEntry* kernelDriver = s_krnlCache->push_next();

                kernelDriver->start = (uint64_t)dev[i];
                kernelDriver->end = 0;
                kernelDriver->name = buf;
                kernelDriver->path = nullptr;
                kernelDriver->degugModuleField = {};

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

                    kernelDriver->path = CopyStringFast(path);

                    if (SymLoadModuleEx(s_DbgHelpSymHandle, nullptr, path, nullptr, (DWORD64)dev[i], 0, nullptr, 0))
                    {
                        GetModuleInfoFromDbgHelp(path, kernelDriver);
                        // We no longer need it if we resolve symbols offline, unload it.
                        if (s_shouldResolveSymbolsOffline) {
                            SymUnloadModule64(s_DbgHelpSymHandle, (DWORD64)dev[i]);
                        }
                    }
                }

                assert(kernelDriver->end == 0 && "kernel end should be zero");
                cnt++;
            }
        }
        std::sort(s_krnlCache->begin(), s_krnlCache->end(), [](const ModuleCacheEntry& lhs, const ModuleCacheEntry& rhs) { return lhs.start > rhs.start; });
    }
}

static void CacheProcessModules()
{
    DWORD needed;
    HANDLE proc = GetCurrentProcess();
    HMODULE mod[1024];
    if (EnumProcessModules(proc, mod, sizeof(mod), &needed) != 0)
    {
        const auto sz = needed / sizeof(HMODULE);
        for (size_t i = 0; i < sz; i++)
        {
            MODULEINFO info;
            if (GetModuleInformation(proc, mod[i], &info, sizeof(info)) != 0)
            {
                char name[1024];
                const auto nameLength = GetModuleFileNameA(mod[i], name, 1021);
                if (nameLength > 0)
                {
                    // This may be a new module loaded since our call to SymInitialize.
                    // Just in case, force DbgHelp to load its pdb !

                    if (!s_shouldResolveSymbolsOffline)
                    {
                        auto moduleCache = LoadSymbolsForModuleAndCache(name, nameLength, (DWORD64)info.lpBaseOfDll, info.SizeOfImage);

                    }
                    else
                    {
                        uint64_t baseAdd = (DWORD64)info.lpBaseOfDll;

                    }

                }
            }
        }
    }
}

void InitCallstack()
{
    s_serverLocalResolve = IsEnv(SERVER_LOCAL_RESOLVE);
    s_clientSendImageInfo = IsEnv(CLIENT_SEND_IMAGES_INFO);


#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
    s_shouldResolveSymbolsOffline = ShouldResolveSymbolsOffline();
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

    s_imageCacheWindows = (ImageCache*)tracy_malloc(sizeof(ImageCache));
    new(s_imageCacheWindows) ImageCache(ImageCacheBaseCapacity);
    s_krnlCache = (FastVector<ModuleCacheEntry>*)tracy_malloc(sizeof(FastVector<ModuleCacheEntry>));
    new(s_krnlCache) FastVector<ModuleCacheEntry>(ImageCacheBaseCapacity);

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
    if (!initTimeModuleLoad)
    {
        TracyDebug("TRACY: skipping init time dbghelper module load\n");
    }
    
    std::lock_guard<std::recursive_mutex> mutexguard{ s_cacheMutex };

    if (initTimeModuleLoad)
    {
        CacheProcessDrivers();
        CacheProcessModules();
    }

#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_UNLOCK;
#endif
#endif
}

void FreeKernelCache()
{
	if (s_krnlCache == nullptr)
	{
		return;
	}

	for (auto& it : *s_krnlCache)
	{
        DestroyModuleCacheEntry(it);
	}
    tracy_free((void*)s_krnlCache);
	s_krnlCache = nullptr;
}

void EndCallstack()
{
    FreeKernelCache();

    if (s_imageCacheWindows != nullptr)
    {
        s_imageCacheWindows->~ImageCache();
        tracy_free(s_imageCacheWindows);
        s_imageCacheWindows = nullptr;
    }
    if (s_DbgHelpSymHandle)
    {
        SymCleanup(s_DbgHelpSymHandle);
        s_DbgHelpSymHandle = 0;
    }
}

const char* DecodeCallstackPtrFast(uint64_t ptr)
{
    if (s_shouldResolveSymbolsOffline) return "[unresolved]";

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

const char* GetKernelModulePath(uint64_t addr)
{
    assert(addr >> 63 != 0);
    if (!s_krnlCache) return nullptr;
    auto it = std::lower_bound(s_krnlCache->begin(), s_krnlCache->end(), addr, [](const ModuleCacheEntry& lhs, const uint64_t& rhs) { return lhs.start > rhs; });
    if (it == s_krnlCache->end()) return nullptr;
    return it->path;

}
bool LoadFromPdb(const char* moduleName, uint64_t baseAddress, uint64_t dllSize, DebugFormat debugFormat, const uint8_t* debugData, uint32_t debugDataSize)
{
    assert(debugFormat == DebugFormat::PdbDebugFormat);

    const uint32_t DataForDebugSize = static_cast<const uint32_t>(debugDataSize);
    assert(moduleName != nullptr);

    const tracy::WindowsDebugData* windowsDebugData = (const tracy::WindowsDebugData*)(debugData);
    const size_t pdbPathLength = debugDataSize - sizeof(tracy::WindowsDebugData);
    const uint8_t* pdbPath = debugData + sizeof(tracy::WindowsDebugData);

    static_assert(sizeof(WindowsDebugData) == 32, "Structure changed or not properly packed");

    static_assert(offsetof(CV_INFO_PDB70, CvSignature) == offsetof(TracyPdbInfo, CvSignature), "Mismatch with DbgHelp headers.");
    static_assert(offsetof(CV_INFO_PDB70, Signature) == offsetof(TracyPdbInfo, Signature), "Mismatch with DbgHelp headers.");
    static_assert(offsetof(CV_INFO_PDB70, Age) == offsetof(TracyPdbInfo, Age), "Mismatch with DbgHelp headers.");
    static_assert(offsetof(CV_INFO_PDB70, PdbFileName) == sizeof(TracyPdbInfo), "Mismatch with DbgHelp headers.");

    const uint32_t sizeOfPdbData = DataForDebugSize - offsetof(WindowsDebugData, cvInfo);

    auto const debug_module_info_size = sizeof(IMAGE_DEBUG_DIRECTORY) + sizeOfPdbData;
    auto const debug_module_info_size_aligned = (debug_module_info_size + mandatoryAlignment) & (~uint64_t(mandatoryAlignment - 1));

    std::vector<uint8_t> dataAligned;
    dataAligned.resize(debug_module_info_size_aligned);

    IMAGE_DEBUG_DIRECTORY* info = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(dataAligned.data());

    info->TimeDateStamp = windowsDebugData->exeDataTimeStamp;
    info->Characteristics = 0;
    info->MajorVersion = windowsDebugData->majorVersion;
    info->MinorVersion = windowsDebugData->minorVersion;
    info->Type = IMAGE_DEBUG_TYPE_CODEVIEW;
    info->AddressOfRawData = 0;
    info->PointerToRawData = sizeof(IMAGE_DEBUG_DIRECTORY);
    info->SizeOfData = sizeOfPdbData;

    memcpy(dataAligned.data() + info->PointerToRawData, &windowsDebugData->cvInfo, sizeOfPdbData);

    MODLOAD_DATA module_load_info;
    module_load_info.ssize = sizeof(module_load_info);
    module_load_info.ssig = DBHHEADER_DEBUGDIRS;
    module_load_info.data = dataAligned.data();
    module_load_info.size = static_cast<DWORD>(dataAligned.size());
    module_load_info.flags = 0;

    const CV_INFO_PDB70* dummie = reinterpret_cast<const CV_INFO_PDB70*>(&windowsDebugData->cvInfo);


    DWORD64 loaddedModule = SymLoadModuleEx(s_DbgHelpSymHandle, NULL, moduleName, NULL, baseAddress,
        dllSize, &module_load_info, 0);

    IMAGEHLP_MODULEW64 modulInfoDebug{};

    modulInfoDebug.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);

    if (SymGetModuleInfoW64(s_DbgHelpSymHandle, loaddedModule, &modulInfoDebug) == TRUE)
    {
        if (modulInfoDebug.SymType != SymNone)
        {
            return true;
        }
    }
    return false;
}

bool IsKernelAddress(uint64_t addr) {
    return (addr >> 63) != 0;
}

// Called from the profiler (server) only, we received data from the client.
void CacheModuleAndLoadExternal(ModuleCacheEntry& moduleCacheEntry)
{
    
    if (!s_serverLocalResolve)
    {
        DestroyModuleCacheEntry(moduleCacheEntry);
        return;
    }

#if 1 // windows
    if (IsKernelAddress(moduleCacheEntry.start))
    {
        ModuleCacheEntry& newKernel = *s_krnlCache->push_next();
        newKernel = moduleCacheEntry;
    }
    else
    {
        s_imageCacheWindows->CacheModuleWithDebugInfo(moduleCacheEntry);
    }
#endif

    bool hasSymbolInfo = false;
    if (moduleCacheEntry.degugModuleField.debugFormat == DebugFormat::PdbDebugFormat)
    {
        hasSymbolInfo = LoadFromPdb(moduleCacheEntry.name, moduleCacheEntry.start, moduleCacheEntry.end - moduleCacheEntry.start,
            moduleCacheEntry.degugModuleField.debugFormat, moduleCacheEntry.degugModuleField.debugData, moduleCacheEntry.degugModuleField.debugDataSize);
    }

    if (!hasSymbolInfo)
    {
        // TODO: load from path only if we can check we got the correct binary (check timestamp / guid ?)
        //DbgHelpLoadSymbolsForModule(moduleCacheEntry.path, moduleCacheEntry.start, moduleCacheEntry.end - moduleCacheEntry.start);
    }
   
}

void CacheModuleKernelAndLoadExternal(const ModuleCacheEntry& kernelDriver)
{
    if(!s_serverLocalResolve)
        return;

    
    bool hasSymbolInfo = false;
    if (kernelDriver.degugModuleField.debugFormat == DebugFormat::PdbDebugFormat)
    {
        hasSymbolInfo = LoadFromPdb(kernelDriver.path, kernelDriver.start, 0, kernelDriver.degugModuleField.debugFormat, kernelDriver.degugModuleField.debugData, kernelDriver.degugModuleField.debugDataSize);
    }

    if (!hasSymbolInfo)
    {
        // TODO: load from path only if we can check we got the correct binary (check timestamp / guid ?)
        //DbgHelpLoadSymbolsForModule(kernelDriver.path, kernelDriver.start, 0);
    }

}

CallstackSymbolData DecodeSymbolAddress(uint64_t ptr)
{
    CallstackSymbolData sym;

    if (s_shouldResolveSymbolsOffline)
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
    const auto res = SymGetLineFromAddr64(s_DbgHelpSymHandle, ptr, &displacement, &line);
    if (res == 0 || line.LineNumber >= 0xF00000)
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

const FastVector<ModuleCacheEntry>& GetModuleData()
{
    return s_imageCacheWindows->GetModuleData();
}

const FastVector<ModuleCacheEntry>& GetKernelDriver()
{
    return *s_krnlCache;
}

CallstackEntryData DecodeCallstackPtr(uint64_t ptr, DecodeCallStackPtrStatus* _decodeCallStackPtrStatus)
{
#ifdef TRACY_DBGHELP_LOCK
    DBGHELP_LOCK;
#endif

    InitRpmalloc();

    bool reseachFailed = false;
    const ModuleNameAndBaseAddress moduleNameAndAddress = GetModuleNameAndPrepareSymbols(ptr, &reseachFailed);


    if (reseachFailed)
    {
        *_decodeCallStackPtrStatus = DecodeCallStackPtrStatus::ModuleMissing;
    }

    if (s_shouldResolveSymbolsOffline || reseachFailed)
    {
#ifdef TRACY_DBGHELP_LOCK
        DBGHELP_UNLOCK;
#endif
        // may use symLen for base adress
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

    char buf[sizeof(SYMBOL_INFO) + MaxNameSize];
    auto si = (SYMBOL_INFO*)buf;
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = MaxNameSize;


    const auto symValid = SymFromAddr(proc, ptr, nullptr, si) != 0;

    if (!symValid)
    {
        *_decodeCallStackPtrStatus = DecodeCallStackPtrStatus::SymbolMissing;
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

void FindModuleFromAddr(uint64_t addr, const ModuleCacheEntry** entry)
{
    *entry = s_imageCacheWindows->FindEntryFromAddr(addr);
}

void FindKernelDriverFromAddr(uint64_t addr, const ModuleCacheEntry** outDrive)
{
    auto it = std::lower_bound(s_krnlCache->begin(), s_krnlCache->end(), addr, [](const ModuleCacheEntry& lhs, const uint64_t& rhs) { return lhs.start > rhs; });
    if (it != s_krnlCache->end())
    {
        *outDrive = it;
    }
}



#elif TRACY_HAS_CALLSTACK == 2 || TRACY_HAS_CALLSTACK == 3 || TRACY_HAS_CALLSTACK == 4 || TRACY_HAS_CALLSTACK == 6

enum { MaxCbTrace = 64 };

struct backtrace_state* cb_bts = nullptr;

int cb_num;
CallstackEntry cb_data[MaxCbTrace];
int cb_fixup;
#ifdef TRACY_USE_IMAGE_CACHE
static ImageCache* s_imageCache = nullptr;
#endif //#ifdef TRACY_USE_IMAGE_CACHE

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
    s_imageCache = (ImageCache*)tracy_malloc( sizeof( ImageCache ) );
    new(s_imageCache) ImageCache();
#endif //#ifdef TRACY_USE_IMAGE_CACHE

#ifndef TRACY_SYMBOL_OFFLINE_RESOLVE
    s_shouldResolveSymbolsOffline = ShouldResolveSymbolsOffline();
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
    if( s_imageCache )
    {
        s_imageCache->~ImageCache();
        tracy_free( s_imageCache );
    }
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

CallstackEntryData DecodeCallstackPtr( uint64_t ptr )
{
    InitRpmalloc();
    if( ptr >> 63 == 0 )
    {
        const char* imageName = nullptr;
        uint64_t imageBaseAddress = 0x0;

#ifdef TRACY_USE_IMAGE_CACHE
        const auto* image = s_imageCache->GetImageForAddress((void*)ptr);
        if( image )
        {
            imageName = image->m_name;
            imageBaseAddress = uint64_t(image->m_startAddress);
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
