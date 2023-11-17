#ifndef __SYMBOLRESOLVER_HPP__
#define __SYMBOLRESOLVER_HPP__

#include <string>
#include <vector>

namespace tracy
{
    struct CallstackFrame;
    class Worker;
}

class SymbolResolver;

SymbolResolver* CreateResolver();
void DestroySymbolResolver(SymbolResolver* resolver);

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

bool ResolveSymbols(SymbolResolver* resolver, const char* imageName,
                    const FrameEntryList& inputEntryList,
                    SymbolEntryList& resolvedEntries);

bool PatchSymbols(SymbolResolver* resolver, tracy::Worker& worker, bool verbose = false);

#endif // __SYMBOLRESOLVER_HPP__