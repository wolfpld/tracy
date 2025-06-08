#if defined(LIBDW_OFFLINE_SYMBOL_RESOLUTION_SUPPORT) && !defined(_WIN32)

#include "OfflineSymbolResolver.h"

#include <iostream>
#include <string>
#include <fstream>
#include <iostream>
#include <string>
#include <array>
#include <sstream>
#include <memory>
#include <limits>
#include <algorithm>
#include <stdio.h>
#include <cxxabi.h>
#include <stdlib.h>
#include <iostream>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <link.h>
#include <dlfcn.h>
#include <string.h>

// libdw
#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <dwarf.h>

static char *debuginfo_path = nullptr;
static const Dwfl_Callbacks offline_callbacks = {
    // We use this table for core files too.
    .find_elf = dwfl_build_id_find_elf,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .section_address = dwfl_offline_section_address,
    .debuginfo_path = &debuginfo_path,
};

// Helper to reolve symbols for a shared lib
struct LibDWResolver
{
public:
    static bool resolveSymbolsForImage( const std::string& imagePath, const FrameEntryList& inputEntryList,
                                        SymbolEntryList& resolvedEntries )
    {
        resolvedEntries.clear();
        LibDWResolver resolverForSo(imagePath.c_str());

        for ( const FrameEntry& entry : inputEntryList)
        {
            LibDWResolver::SymbolInfo symbol;
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
                std::cout << "LIBDW: resolved symbol: 0x" << std::hex << entry.symbolOffset << std::dec << " of '" << imagePath << "'" 
                          << ", function: '" << newEntry.name << "' | '" << newEntry.file << "':" << newEntry.line << std::endl;
            #endif //#ifdef VERBOSE_LOG
            }
            else
            {
                newEntry.name = "[unknown] + " + std::to_string(entry.symbolOffset);

            #ifdef VERBOSE_LOG
                std::cout << "LIBDW: failed to resolve symbol: 0x" << std::hex << entry.symbolOffset << std::dec << " of '" 
                          << imagePath << "'"  << std::endl; 
            #endif //#ifdef VERBOSE_LOG
            }

            resolvedEntries.push_back( std::move(newEntry) );
        }

        return true;
    }

private:
    Dwfl *dwfl = nullptr;

    struct SymbolInfo 
    {
        std::string function_name;
        std::string file_name;
        int line_number;
    };

    static void print_dwfl_error(const char *msg) {
        auto err = dwfl_errno();
        std::cerr << msg << ": " << dwfl_errmsg(err) << std::endl;
    }

    // c++ name demangling
    static const char* demangle( const char* mangled )
    {
        constexpr size_t demangle_buffer_len = 1024*1024;
        static char demangle_buffer[demangle_buffer_len];

        if( !mangled || mangled[0] != '_' ) 
            return nullptr;
        if( strlen( mangled ) > demangle_buffer_len ) 
            return nullptr;
        int status;
        size_t len = demangle_buffer_len;
        return abi::__cxa_demangle( mangled, demangle_buffer, &len, &status );
    }

    LibDWResolver(const char* so_path)
    {
        dwfl = dwfl_begin(&offline_callbacks);
        if (!dwfl)
        {
            print_dwfl_error("dwfl_begin() failed");
            return;
        }
    
        if (!dwfl_report_elf(dwfl, so_path, so_path, -1, 0, 0)) 
        {
            print_dwfl_error("dwfl_report_offline() failed");
            return;
        }

        if (dwfl_report_end(dwfl, NULL, NULL))
        {
            print_dwfl_error("dwfl_report_end() failed");
            return;
        }  

        Dwfl_Module *mod = dwfl_addrmodule(dwfl, 0x0);
        buildExportedSymbolsList(mod);
    }

    ~LibDWResolver()
    {
        if (dwfl)
        {
            dwfl_end(dwfl);
        }
    }

    bool resolveSymbol(uintptr_t offset, SymbolInfo& info) 
    {
        if (!dwfl) 
        {
            return false;
        }

        Dwfl_Module *mod = dwfl_addrmodule(dwfl, offset);
        if (!mod)
        {
            print_dwfl_error("dwfl_addrmodule() failed");
            return false;
        }

        Dwarf_Addr bias{};
        dwfl_module_getdwarf(mod, &bias);
        Dwarf_Addr addr = offset + bias;
    
        // do full resolve first using DWARF symbol info
        if (resolveWithDebugSymbols(mod, addr, info))
        {
            return true;
        }
        // fallback to ELF exported symbols
        else if (getFunctionNameFromElfExportedSymbols(mod, offset, info))
        {
            return true;
        }
        return false;
    }

    // full DWARD debug info symbol decoding (including inlines)
    bool resolveWithDebugSymbols(Dwfl_Module *mod, Dwarf_Addr addr, SymbolInfo& info)
    {
        const char* function_name = nullptr;
        const char* file_name = nullptr;
        int line_number = 0;

        if (resolveSymbolFromSymtab(mod, addr, function_name, file_name, line_number))
        {
            //getInlineSymbol(mod, addr, function_name, file_name, line_number);
        }

        if (function_name)
        {
            info.function_name = function_name;
            if(file_name)
                info.file_name = file_name;
            info.line_number = (unsigned int)line_number;
            return true;
        }

        return false;
    }

   // match exported symbols ex: .symtab
   bool resolveSymbolFromSymtab(Dwfl_Module *mod, Dwarf_Addr addr,
                                const char*& function_name, const char*& file_name,
                                int& line_number)
   {
       function_name = dwfl_module_addrname(mod, addr);
       if (function_name)
       {
           Dwfl_Line* line = dwfl_module_getsrc(mod, addr);
           if (!line)
           {
               line = dwfl_getsrc(dwfl, addr);
           }
           if (line)
           {
              file_name = dwfl_lineinfo(line, nullptr, &line_number, nullptr, nullptr, nullptr);
           }
           return true;
       }
       return false;
   }

    // match exported symbols ex: .symtab
    bool resolveSymbolFromSymtab(Dwfl_Module *mod, Dwarf_Addr addr, SymbolInfo& info)
    {
        const char* funcname = nullptr;
        const char *filename = nullptr;
        int line_number = 0;
        if (resolveSymbolFromSymtab(mod, addr, funcname, filename, line_number))
        {
            info.function_name = funcname;
            if(filename)
                info.file_name = filename;
            info.line_number = (unsigned int)line_number;
            return true;
        }
        return false;
    }

    // get inlined symbols
    bool getInlineSymbol(Dwfl_Module *mod, Dwarf_Addr addr, 
                         const char*& function_name, const char*& file_name,
                         int& line_number)
    {
        Dwarf_Addr bias = 0;
        Dwarf_Die* cudie = dwfl_module_addrdie(mod, addr, &bias);

        // This function retrieves the scopes (DIEs) that are relevant to a specific address. 
        // Scopes can include functions, lexical blocks, inlined subroutines,
        // and other constructs that define a range of addresses in the code.
        Dwarf_Die* scopes = nullptr;
        int nscopes = dwarf_getscopes(cudie, addr - bias, &scopes);
        if (nscopes <= 0)
            return false;

        Dwarf_Die subroutine;
        Dwarf_Off dieoff = dwarf_dieoffset(&scopes[0]);
        dwarf_offdie(dwfl_module_getdwarf(mod, &bias), dieoff, &subroutine);
        free(scopes);
        scopes = nullptr;

        nscopes = dwarf_getscopes_die(&subroutine, &scopes);
        if (nscopes <= 1)
        {
            free(scopes);
            return false;
        }
        
        Dwarf_Die cu;
        Dwarf_Files *files;
        if (dwarf_diecu(&scopes[0], &cu, nullptr, nullptr) == nullptr ||
            dwarf_getsrcfiles(cudie, &files, nullptr) != 0)
        {
            free(scopes);
            return false;
        }

        for (int i = 0; i < nscopes - 1; i++)
        {
            Dwarf_Word val;
            Dwarf_Attribute attr;
            Dwarf_Die *die = &scopes[i];
            if (dwarf_tag(die) != DW_TAG_inlined_subroutine)
                continue;

            // Search for the parent inline or function. 
            // It might not be directly above this inline -- e.g. there could be a lexical_block in between.
            for (int j = i + 1; j < nscopes; j++)
            {
                Dwarf_Die *parent = &scopes[j];
                int tag = dwarf_tag(parent);
                if (tag == DW_TAG_inlined_subroutine || tag == DW_TAG_entry_point || tag == DW_TAG_subprogram)
                {
                    Dwarf_Attribute attr;
                    function_name = dwarf_formstring(dwarf_attr_integrate(die, DW_AT_linkage_name, &attr));
                    break;
                }
            }

            if (function_name)
            {
                if (dwarf_formudata(dwarf_attr(die, DW_AT_call_file, &attr), &val) == 0)
                    file_name = dwarf_filesrc(files, val, NULL, NULL);
                if (dwarf_formudata(dwarf_attr(die, DW_AT_call_line, &attr), &val) == 0)
                    line_number = val;
                
                free(scopes);
                return true;
            }
        }
        free(scopes);
        return false;
    }

    struct ExportedSymbolInfo {
        const char* name;
        uintptr_t address;
        size_t size;
    };
    std::vector<ExportedSymbolInfo> symbols_;

    bool getFunctionNameFromElfExportedSymbols(Dwfl_Module *mod, uintptr_t offset, SymbolInfo& info)
    {
        ExportedSymbolInfo* exportedSymbol = getExportedSymbolByAddress(offset);
        if(exportedSymbol)
        {
            //std::cout << "Found matching sym: '" << exportedSymbol->name << "':" << std::hex << "0x" << exportedSymbol->address << "-" 
            //          << "0x" << (exportedSymbol->address + exportedSymbol->size) << "'" << std::dec << std::endl;
            info.function_name = exportedSymbol->name;
            return true;
        }
        return false;
    }

    void buildExportedSymbolsList(Dwfl_Module *mod)
    {
        symbols_.clear();

        int sym_idx = 0;
        GElf_Sym sym;
        const char* symName = nullptr;
        while ((symName = dwfl_module_getsym(mod, sym_idx++, &sym, nullptr)) != nullptr) 
        {
            // Only consider function and object symbols
            unsigned char sym_type = GELF_ST_TYPE(sym.st_info);
            if ( (sym_type == STT_FUNC || sym_type == STT_OBJECT) &&
                sym.st_value != 0x0 && sym.st_size != 0x0)
            {
                //std::cout << "sym: '" << symName << "':" << std::hex << "0x" << sym.st_value << "-" 
                //          << "0x" << (sym.st_value + sym.st_size) << "'" << std::endl;

                ExportedSymbolInfo newSymbol{symName, uintptr_t(sym.st_value), size_t(sym.st_size)};
                symbols_.push_back(newSymbol);
            }
        }

        std::sort(symbols_.begin(), symbols_.end(), [](const ExportedSymbolInfo &a, const ExportedSymbolInfo &b) {
            return a.address < b.address;
        });
    }

    // use the exported symbols start addresses as the sizes generally are not right, so we match a symbol that falls in
    // between the adress start range of 2 consecutive symbols
    ExportedSymbolInfo* getExportedSymbolByAddress(uintptr_t offset)
    {
        auto it = std::lower_bound(symbols_.begin(), symbols_.end(), offset, [](const ExportedSymbolInfo &symbol, uintptr_t offset) {
            return symbol.address < offset;
        });

        if (it != symbols_.begin()) 
        {
            --it;
            if (offset >= it->address ) 
            {
                return &(*it);
            }
        }
        return nullptr;
    }
};

bool ResolveSymbolsWithLibDW( const std::string& imagePath, const FrameEntryList& inputEntryList,
                              SymbolEntryList& resolvedEntries )
{
    return LibDWResolver::resolveSymbolsForImage( imagePath, inputEntryList, resolvedEntries );
}

#endif // #ifdef LIBDW_OFFLINE_SYMBOL_RESOLUTION_SUPPORT && !defined(_WIN32)