#if defined(LIBBACKTRACE_OFFLINE_SYMBOL_RESOLUTION_SUPPORT) && !defined(_WIN32)

#include "OfflineSymbolResolver.h"

#include <fstream>
#include <iostream>
#include <string>
#include <array>
#include <sstream>
#include <memory>
#include <limits>
#include <algorithm>
#include <stdio.h>
#include <dlfcn.h>
#include <cxxabi.h>
#include <stdlib.h>
#include <iostream>
#include <dlfcn.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

// include lib backtrace code. TODO: move to it's own file!
#define TRACY_LIBBACKTRACE_ELF_DYNLOAD_SUPPORT
#include "../../public/libbacktrace/alloc.cpp"
#include "../../public/libbacktrace/dwarf.cpp"
#include "../../public/libbacktrace/fileline.cpp"
#include "../../public/libbacktrace/mmapio.cpp"
#include "../../public/libbacktrace/posix.cpp"
#include "../../public/libbacktrace/sort.cpp"
#include "../../public/libbacktrace/state.cpp"
#include "../../public/libbacktrace/elf.cpp"

//#define VERBOSE_LOG

using namespace tracy;

// Structure to hold search parameters for dl_iterate_phdr
struct FindBaseAddressData {
    const char* so_path;
    uintptr_t base_address = 0;
};

// dl_iterate_phdr callback to find the base address of the shared object
int find_base_address_callback(struct dl_phdr_info* info, size_t, void* data) {
    auto* find_data = static_cast<FindBaseAddressData*>(data);
    if (strstr(info->dlpi_name, find_data->so_path) != nullptr) {
        find_data->base_address = info->dlpi_addr;
        return 1;  // Stop iterating
    }
    return 0;  // Continue iterating
}

// Get the base address of the shared object
uintptr_t get_so_base_address(const char* so_path) {
    FindBaseAddressData data{so_path, 0};
    dl_iterate_phdr(find_base_address_callback, &data);
    
    if (data.base_address == 0) 
    {
        std::cerr << "Failed to find base address of '" << so_path << "'" << std::endl;
    }
    return data.base_address;
}

// demangling
constexpr size_t demangle_buffer_len = 1024*1024;
char demangle_buffer[demangle_buffer_len];
const char* demangle( const char* mangled )
{
    if( !mangled || mangled[0] != '_' ) 
        return nullptr;
    if( strlen( mangled ) > demangle_buffer_len ) 
        return nullptr;
    int status;
    size_t len = demangle_buffer_len;
    return abi::__cxa_demangle( mangled, demangle_buffer, &len, &status );
}

struct tracy::backtrace_state* backtraceState = nullptr;

void* dlopen_wrapper(const char* path, int flag) {
    // Buffer to hold the resolved path
    char resolved_path[PATH_MAX];

    // Resolve the symbolic link to its real path
    if (realpath(path, resolved_path) == NULL) 
    {
        std::cerr << "Error resolving real path: '" << path << "'" << std::endl;
        return nullptr;
    }

    // Call dlopen with the resolved path
    void* handle = dlopen(resolved_path, flag);
    if (!handle) 
    {
        std::cerr << "Error loading library: '" << resolved_path << "', error: '" << dlerror() << "'" << std::endl;
    }
    else
    {
        std::cerr << "dlopen ok for: '" << resolved_path << "'" << std::endl;
    }

    return handle;
}

// Helper to reolve symbols for a shared lib
struct BacktraceSoResolver
{
    struct SymbolInfo 
    {
        std::string function_name;
        std::string file_name;
        int line_number;
        bool resolved = false;
    };

    BacktraceSoResolver(const char* so_path)
    {
        // Load the shared object, we need it's base address to use our offsets off it
        handle = dlopen_wrapper(so_path, RTLD_LAZY | RTLD_LOCAL);
        if (!handle) 
        {
            std::cerr << "Failed to load SO:' " << so_path << std::endl;
            return;
        }

        base_address = get_so_base_address(so_path);
    #ifdef VERBOSE_LOG
        std::cout << "Library: " << so_path << std::endl;
        std::cout << "Base Address: 0x" << std::hex << base_address << std::dec << std::endl;
    #endif //#ifdef VERBOSE_LOG

        if (!backtraceState)
        {
            backtraceState = backtrace_create_state(nullptr, 0, errorCallback, nullptr);
            if (!backtraceState) 
            {
                std::cerr << "Failed to initialize backtrace state" << std::endl;
                return;
            }
        }
    }

    ~BacktraceSoResolver()
    {
        if(handle)
        {
            //dlclose(handle);
        }
    }

    static bool resolveSymbolsForImage( const std::string& imagePath, const FrameEntryList& inputEntryList,
                                        SymbolEntryList& resolvedEntries )
    {
        resolvedEntries.clear();
        BacktraceSoResolver resolverForSo(imagePath.c_str());

        for ( const FrameEntry& entry : inputEntryList)
        {
            BacktraceSoResolver::SymbolInfo symbol;
            const bool resolved = resolverForSo.resolveSymbol(entry.symbolOffset, symbol);

            SymbolEntry newEntry;
            newEntry.resolved = resolved;
            if(resolved)
            {
                const char* demangledVersion = demangle(symbol.function_name.c_str());
                newEntry.name = demangledVersion ? demangledVersion : symbol.function_name;
                newEntry.file = symbol.file_name;
                newEntry.line = symbol.line_number;
            #ifdef VERBOSE_LOG
                std::cout << "resolved symbol: 0x" << std::hex << entry.symbolOffset << std::dec << " of '" << imagePath << "'" 
                          << ", function: '" << newEntry.name << "' | '" << newEntry.file << "':" << newEntry.line << std::endl;
            #endif //#ifdef VERBOSE_LOG
            }
            else
            {
            #ifdef VERBOSE_LOG
                std::cout << "failed to resolve symbol: 0x" << std::hex << entry.symbolOffset << std::dec << " of '" 
                          << imagePath << "'"  << std::endl; 
            #endif //#ifdef VERBOSE_LOG
            }

            resolvedEntries.push_back( std::move(newEntry) );
        }

        return true;
    }

private:

    bool resolveSymbol(uintptr_t address, SymbolInfo& info) 
    {
        if (!backtraceState) 
        {
            std::cerr << "Backtrace was not initialized!\n";
            return false;
        }

        uintptr_t absolute_address = base_address + address;
        backtrace_pcinfo(backtraceState, absolute_address, symbolCallback, errorCallback, &info);

        if (!info.resolved)
        {
            // Use dladdr to get function name
            Dl_info dl_info;
            if (dladdr((void*)absolute_address, &dl_info)) 
            {
                if (dl_info.dli_sname)
                {
                    info.function_name = dl_info.dli_sname;
                    info.resolved = true;
                }
            #ifdef VERBOSE_LOG
                std::cout << "dladdr Symbol: " << (dl_info.dli_sname ? dl_info.dli_sname : "Unknown") << std::endl;
            #endif //#ifdef VERBOSE_LOG
            } 
            else 
            {
            #ifdef VERBOSE_LOG
                std::cerr << "dladdr failed to find function name" << std::endl;
            #endif //#ifdef VERBOSE_LOG
            }
        }

        return info.resolved;
    }

    // Callback function for symbol resolution
    static int symbolCallback(void* data, uintptr_t pc, uintptr_t lowaddr, const char* filename, int lineno, const char* function )
    {
    #ifdef VERBOSE_LOG
        std::cout << pc << "| 0x" << std::hex << lowaddr << std::dec 
                  << "|" << (filename?filename:"<nullptr>") << "|" <<  lineno << "|" << (function?function:"<nullptr>") << std::endl;
    #endif //#ifdef VERBOSE_LOG
        SymbolInfo* info = static_cast<SymbolInfo*>(data);
        if (function) info->function_name = function;
        if (filename) info->file_name = filename;
        info->line_number = lineno;
        info->resolved = (function != nullptr);
        return 1;
    }

    // Error callback
    static void errorCallback(void* /*data*/, const char* msg, int errnum) 
    {
        std::cerr << "libbacktrace error: " << msg << " (Error Code: " << errnum << ")\n";
    }

    void* handle = nullptr;
    uintptr_t base_address = 0x0;
};

bool ResolveSymbolsWithLibBacktrace( const std::string& imagePath, const FrameEntryList& inputEntryList,
                                     SymbolEntryList& resolvedEntries )
{
    return BacktraceSoResolver::resolveSymbolsForImage( imagePath, inputEntryList, resolvedEntries );
}

#endif // #if defined(LIBBACKTRACE_OFFLINE_SYMBOL_RESOLUTION_SUPPORT) && !defined(_WIN32)