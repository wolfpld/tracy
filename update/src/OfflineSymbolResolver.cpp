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

bool ApplyPathSubstitutions( std::string& path, const PathSubstitutionList& pathSubstitutionlist )
{
    for( const auto& substitution : pathSubstitutionlist )
    {
        if( std::regex_match(path, substitution.first) )
        {
            path = std::regex_replace( path, substitution.first, substitution.second );
            return true;
        }
    }
    return false;
}

tracy::StringIdx AddSymbolString( tracy::Worker& worker, const std::string& str )
{
    // TODO: use string hash map to reduce potential string duplication?
    tracy::StringLocation location = worker.StoreString( str.c_str(), str.length() );
    return tracy::StringIdx( location.idx );
}

bool PatchSymbolsWithRegex( tracy::Worker& worker, const PathSubstitutionList& pathSubstitutionlist, bool verbose )
{
    uint64_t callstackFrameCount = worker.GetCallstackFrameCount();
    std::string relativeSoNameMatch = "[unresolved]";

    std::cout << "Found " << callstackFrameCount << " callstack frames. Batching into image groups..." << std::endl;

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

    std::cout << "Batched into " << entriesPerImageIdx.size() << " unique image groups" << std::endl;

    // FIXME: the resolving of symbols here can be slow and could be done in parallel per "image"
    // - be careful with string allocation though as that would be not safe to do in parallel
    for( FrameEntriesPerImageIdx::iterator imageIt = entriesPerImageIdx.begin(),
         imageItEnd = entriesPerImageIdx.end(); imageIt != imageItEnd; ++imageIt )
    {
        tracy::StringIdx imageIdx( imageIt->first );
        std::string imagePath = worker.GetString( imageIdx );

        FrameEntryList& entries = imageIt->second;

        if( !entries.size() ) continue;

        std::cout << "Resolving " << entries.size() << " symbols for image: '" 
                  << imagePath << "'" << std::endl;
        const bool substituted = ApplyPathSubstitutions( imagePath, pathSubstitutionlist );
        if( substituted )
        {
            std::cout << "\tPath substituted to: '" << imagePath << "'" << std::endl;
        }

        SymbolEntryList resolvedEntries;
        ResolveSymbols( imagePath, entries, resolvedEntries );

        if( resolvedEntries.size() != entries.size() )
        {
            std::cerr << " failed to resolve all entries! (got: " 
                      << resolvedEntries.size() << ")" << std::endl;
            continue;
        }

        // finally patch the string with the resolved symbol data
        for ( size_t i = 0; i < resolvedEntries.size(); ++i )
        {
            FrameEntry& frameEntry = entries[i];
            const SymbolEntry& symbolEntry = resolvedEntries[i];

            tracy::CallstackFrame& frame = *frameEntry.frame;

            if( !symbolEntry.name.length() ) continue;

            if( verbose )
            {
                const char* nameStr = worker.GetString( frame.name );
                std::cout << "patching '" << nameStr << "' of '" << imagePath 
                          << "' -> '" << symbolEntry.name << "'" << std::endl;
            }

            frame.name = AddSymbolString( worker, symbolEntry.name );
            const char* newName = worker.GetString( frame.name );

            if( symbolEntry.file.length() )
            {
                frame.file = AddSymbolString( worker, symbolEntry.file );
                frame.line = symbolEntry.line;
            }
        }
    }

    return true;
}

void PatchSymbols( tracy::Worker& worker, const std::vector<std::string>& pathSubstitutionsStrings, bool verbose )
{
    std::cout << "Resolving and patching symbols..." << std::endl;

    PathSubstitutionList pathSubstitutionList;
    for ( const std::string& pathSubst : pathSubstitutionsStrings )
    {
        std::size_t pos = pathSubst.find(';');
        if ( pos == std::string::npos )
        {
            std::cerr << "Ignoring invalid path substitution: '" << pathSubst
                      << " '(please separate the regex of the string to replace with a ';')" << std::endl;
            continue;
        }

        try
        {
            std::regex reg(pathSubst.substr(0, pos));
            std::string replacementStr(pathSubst.substr(pos + 1));
            pathSubstitutionList.push_back(std::pair(reg, replacementStr));
        }
        catch ( std::exception& e )
        {
            std::cerr << "Ignoring invalid path substitution: '" << pathSubst
                      << "' (" << e.what() << ")" << std::endl;
            continue;
        }
    }

    if ( !PatchSymbolsWithRegex(worker, pathSubstitutionList, verbose) )
    {
        std::cerr << "Failed to patch symbols" << std::endl;
    }
}