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
};

using SymbolEntryList = std::vector<SymbolEntry>;

// Dispatches to the appropriate backend depending on the platform and whether a custom
// addr2line-compatible tool was specified. When addr2lineToolPath is non-empty, the tool at
// that path is invoked (on any platform); otherwise the platform default is used (DbgHelp on
// Windows, the 'addr2line' found in PATH elsewhere). addr2lineArgs are extra arguments passed
// verbatim to the addr2line-compatible tool (e.g. "--relative-address").
bool ResolveSymbols( const std::string& addr2lineToolPath, const std::string& addr2lineArgs,
                     const std::string& imagePath, const FrameEntryList& inputEntryList,
                     SymbolEntryList& resolvedEntries );

// Backend invoking an addr2line-compatible tool. Available on all platforms. An empty
// addr2lineToolPath falls back to the 'addr2line' found in PATH. addr2lineArgs are inserted
// verbatim into the tool's command line.
bool ResolveSymbolsAddr2Line( const std::string& addr2lineToolPath, const std::string& addr2lineArgs,
                              const std::string& imagePath, const FrameEntryList& inputEntryList,
                              SymbolEntryList& resolvedEntries );

#ifdef _WIN32
// Backend using the Windows DbgHelp library.
bool ResolveSymbolsDbgHelp( const std::string& imagePath, const FrameEntryList& inputEntryList,
                            SymbolEntryList& resolvedEntries );
#endif

// Resets all callstack frame symbols back to the unresolved state ("[unresolved]" / "[unknown]"),
// so a subsequent PatchSymbols pass re-resolves every frame. This is useful to chain several
// resolution passes with different path substitutions. Only meaningful for traces captured with
// TRACY_SYMBOL_OFFLINE_RESOLVE, where each frame's symAddr holds the image-relative offset.
void ResetSymbols( tracy::Worker& worker );

void PatchSymbols( tracy::Worker& worker, const std::vector<std::string>& pathSubstitutionsStrings,
                   const std::string& addr2lineToolPath = std::string(),
                   const std::string& addr2lineArgs = std::string(), bool verbose = false );

using PathSubstitutionList = std::vector<std::pair<std::regex, std::string> >;
bool PatchSymbolsWithRegex( tracy::Worker& worker, const PathSubstitutionList& pathSubstituionlist,
                            const std::string& addr2lineToolPath = std::string(),
                            const std::string& addr2lineArgs = std::string(), bool verbose = false );

#endif // __SYMBOLRESOLVER_HPP__