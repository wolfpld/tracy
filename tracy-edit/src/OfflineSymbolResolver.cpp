#include <fstream>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>

#include "../../server/TracyWorker.hpp"
#include "../../zstd/zstd.h"

#include "OfflineSymbolResolver.h"

// TODO: use string hash map to reduce duplication or use some worker string internal hashing
tracy::StringIdx AddSymbolString(tracy::Worker& worker, const char* str)
{
    uint32_t newStringIdx = worker.AddNewString( str );
    return tracy::StringIdx( newStringIdx );
}

bool PatchSymbols(SymbolResolver* resolver, tracy::Worker& worker, bool verbose)
{
    if( !resolver )
    {
        return false;
    }

    uint64_t callstackFrameCount = worker.GetCallstackFrameCount();
    std::string relativeSoNameMatch = "[unresolved]";

    std::cout << "Found '" << callstackFrameCount << "' callstack frames. Batching into image groups..." << std::endl;

    // batch the symbol queries by .so so we issue the least amount of requests
    using FrameEntriesPerImageIdx = std::unordered_map<uint32_t, FrameEntryList>;
    FrameEntriesPerImageIdx entriesPerImageIdx;

    auto& callstackFrameMap = worker.GetCallstackFrameMap();
    for( auto it = callstackFrameMap.begin(); it != callstackFrameMap.end(); ++it )
    {
        tracy::CallstackFrameData* frameDataPtr = it->second;
        if( !frameDataPtr )
        {
            continue;
        }

        tracy::CallstackFrameData& frameData = *frameDataPtr;
        const char* imageName = worker.GetString( frameData.imageName );

        const uint32_t imageNameIdx = frameData.imageName.Idx();
        FrameEntryList& entries = entriesPerImageIdx[imageNameIdx];

        for( uint8_t f = 0; f < frameData.size; f++ )
        {
            tracy::CallstackFrame& frame = frameData.data[f];

            // TODO: use a better way to identify symbols that are unresolved
            const char* nameStr = worker.GetString(frame.name);
            if( strncmp( nameStr, relativeSoNameMatch.c_str(), relativeSoNameMatch.length() ) == 0 )
            {
                // when doing offline resolving we pass the offset from the start of the shared library in the "symAddr"
                const uint64_t decodedOffset = frame.symAddr;
                entries.push_back( {&frame, decodedOffset} );
            }
        }
    }

    std::cout << "Batched into '" << entriesPerImageIdx.size() << "' unique image groups" << std::endl;

    // FIXME: the resolving of symbols here can be slow and could be done in parallel per "image"
    // - be careful with string allocation though as that would be not safe to do in parallel
    for( FrameEntriesPerImageIdx::iterator imageIt = entriesPerImageIdx.begin(),
         imageItEnd = entriesPerImageIdx.end(); imageIt != imageItEnd; ++imageIt )
    {
        tracy::StringIdx imageIdx( imageIt->first );
        const char* imageName = worker.GetString( imageIdx );

        FrameEntryList& entries = imageIt->second;

        std::cout << "Resolving " << entries.size() << " symbols for image: '" << imageName << "'" << std::endl;

        if(!entries.size())
        {
            continue;
        }

        SymbolEntryList resolvedEntries;
        ResolveSymbols( resolver, imageName, entries, resolvedEntries );

        if( resolvedEntries.size() != entries.size() )
        {
            std::cerr << "ERROR: failed to resolve all entries! (got: " << resolvedEntries.size() << ")" << std::endl;
            continue;
        }

        // finally patch the string with the resolved symbol data
        for (size_t i = 0; i < resolvedEntries.size(); ++i)
        {
            FrameEntry& frameEntry = entries[i];
            const SymbolEntry& symbolEntry = resolvedEntries[i];

            tracy::CallstackFrame& frame = *frameEntry.frame;
            if(!symbolEntry.name.length())
                continue;

            if(verbose)
            {
                const char* nameStr = worker.GetString(frame.name);
                std::cout << "patching '" << nameStr << "' of '" << imageName << "' -> '" << symbolEntry.name << "'" << std::endl;
            }

            frame.name = AddSymbolString(worker, symbolEntry.name.c_str());
            const char* newName = worker.GetString(frame.name);

            if(symbolEntry.file.length())
            {
                frame.file = AddSymbolString(worker, symbolEntry.file.c_str());
                frame.line = symbolEntry.line;
            }
        }
    }

    return true;
}
