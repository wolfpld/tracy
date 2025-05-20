#ifndef __SYMBOLRESOLVER_HPP__
#define __SYMBOLRESOLVER_HPP__

#include <string>
#include <vector>
#include <regex>
#include <cstdint>

namespace tracy
{
    struct CallstackFrame;
    class Worker;
}

struct FrameEntry
{
    tracy::CallstackFrame* frame = nullptr;
    uint64_t symbolOffset = 0;
};

using FrameEntryList = std::vector<FrameEntry>;

struct SymbolEntry
{
    std::string name;
    std::string file;
    int line = 0;
    bool resolved = false;
};

using SymbolEntryList = std::vector<SymbolEntry>;

struct ResolveOptions
{
    bool verbose = false;
    std::string resolver;
    int maxParallelism = -1;
};

int GetOfflineSymbolResolverCount();
const char* GetOfflineSymbolResolverName(int index);
const char* GetDefaultOfflineSymbolResolver();

void PatchSymbols( tracy::Worker& worker, const std::vector<std::string>& pathSubstitutionsStrings,
                   const std::vector<std::string>& skipImageList, const ResolveOptions& options);

using SkipImageList = std::vector<std::regex>;
using PathSubstitutionList = std::vector<std::pair<std::regex, std::string> >;
bool PatchSymbolsWithRegex( tracy::Worker& worker, const PathSubstitutionList& pathSubstituionlist, 
                            const SkipImageList& skipImageList, const ResolveOptions& options);

bool ResolveSymbols( const std::string& imagePath, const FrameEntryList& inputEntryList,
                     SymbolEntryList& resolvedEntries, const ResolveOptions& options);

// for linux we have multiple options:
#ifdef _WIN32
    bool ResolveSymbolsWithDbgHelp(const std::string& imagePath, const FrameEntryList& inputEntryList,
                                   SymbolEntryList& resolvedEntries );
#else
    bool ResolveSymbolsWithLibBacktrace( const std::string& imagePath, const FrameEntryList& inputEntryList,
                                        SymbolEntryList& resolvedEntries );
    bool ResolveSymbolsWithLibDW( const std::string& imagePath, const FrameEntryList& inputEntryList,
                                SymbolEntryList& resolvedEntries );
    bool ResolveSymbolsWithAddr2Line( const std::string& imagePath, const FrameEntryList& inputEntryList,
                                    SymbolEntryList& resolvedEntries );
#endif //#ifndef _WIN32

#endif // __SYMBOLRESOLVER_HPP__