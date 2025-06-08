#include <fstream>
#include <iostream>
#include <vector>
#include <future>
#include <thread>
#include <chrono>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>
#include <zstd.h>

#include "../../server/TracyWorker.hpp"

#include "OfflineSymbolResolver.h"

struct OfflineResolverEntry
{
    const char* name;
    bool (*resolveSymbolsCallback)(const std::string& imagePath, const FrameEntryList& inputEntryList,
                                   SymbolEntryList& resolvedEntries);
};
static OfflineResolverEntry offlineResolverConfig[] = 
{
   // ordered by preference (default is the first one of the list available)
#ifdef _WIN32
    OfflineResolverEntry("dbghelp", &ResolveSymbolsWithDbgHelp),
#else
  #ifdef LIBDW_OFFLINE_SYMBOL_RESOLUTION_SUPPORT
    OfflineResolverEntry("libdw", &ResolveSymbolsWithLibDW),
  #endif // #ifdef LIBDW_OFFLINE_SYMBOL_RESOLUTION_SUPPORT
    OfflineResolverEntry("addr2line", &ResolveSymbolsWithAddr2Line),
  #ifdef LIBBACKTRACE_OFFLINE_SYMBOL_RESOLUTION_SUPPORT
    OfflineResolverEntry("libacktrace", &ResolveSymbolsWithLibBacktrace),
  #endif // #ifdef LIBBACKTRACE_OFFLINE_SYMBOL_RESOLUTION_SUPPORT
#endif //#ifndef _WIN32
};

int GetOfflineSymbolResolverCount()
{
    return sizeof(offlineResolverConfig)/sizeof(offlineResolverConfig[0]);
}
const char* GetOfflineSymbolResolverName(int index)
{
    return (index < GetOfflineSymbolResolverCount()) ? offlineResolverConfig[index].name : "";
}
const char* GetDefaultOfflineSymbolResolver()
{
    return GetOfflineSymbolResolverCount() ? offlineResolverConfig[0].name : "";
}

// main entrypoint to resolving symbols
bool ResolveSymbols( const std::string& imagePath, const FrameEntryList& inputEntryList,
                     SymbolEntryList& resolvedEntries, const ResolveOptions& options)
{
    for (int i = 0; i < GetOfflineSymbolResolverCount(); ++i)
    {
        OfflineResolverEntry& entry = offlineResolverConfig[i];
        if (options.resolver == entry.name)
        {
            return entry.resolveSymbolsCallback(imagePath, inputEntryList, resolvedEntries);
        }
    }
    return false;
}

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

bool ShouldSkipImage( const std::string& imagePath, const SkipImageList* skipImageList ) 
{
    if(!skipImageList)
        return false;

    for( const auto& skipMatch : *skipImageList )
    {
        if( std::regex_match( imagePath, skipMatch ) )
        {
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

using JobCallback = std::function<void(size_t jobIndex)>;
void processJobsInParallel( size_t maxJobs, size_t maxConcurrent, JobCallback&& onJobStart, JobCallback&& func,
                            JobCallback&& onJobEnd )
{
    if (maxConcurrent <=1)
    {
        for(size_t index = 0; index < maxJobs; ++index)
        {
            onJobStart(index);
            func(index);
            onJobEnd(index);
        }
    }

    struct JobEntry
    {
        size_t jobIndex;
        std::future<void> future;
    };

    std::vector<JobEntry> results;
    size_t index = 0;

    while( index < maxJobs || !results.empty() )
    {
        // Launch new jobs if there is room
        while( index < maxJobs && results.size() < maxConcurrent )
        {
            onJobStart( index );
            auto future = std::async( std::launch::async, std::bind( func, index ) ); 
            results.push_back( { index, std::move(future) } );
            index++;
        }

        // Remove completed jobs
        results.erase( std::remove_if( results.begin(), results.end(),
            [onJobEnd]( JobEntry& entry )
            { 
                const bool finished = entry.future.wait_for( std::chrono::milliseconds(0) ) == std::future_status::ready; 
                if (finished)
                {
                    onJobEnd( entry.jobIndex );
                }
                return finished;
            }),
            results.end() );
    }
}

class Stopwatch
{
public:
    explicit Stopwatch()
    : start_(std::chrono::high_resolution_clock::now())
    {}
    void start()
    {
        start_ = std::chrono::high_resolution_clock::now();
    }
    size_t getTimeFromStartInMs() const
    {
        auto end = std::chrono::high_resolution_clock::now();
        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start_).count();
        return durationMs;
    }
private:
    std::chrono::high_resolution_clock::time_point start_;
};

bool PatchSymbolsWithRegex( tracy::Worker& worker, const PathSubstitutionList& pathSubstitutionlist,
                            const SkipImageList* skipImageList, const ResolveOptions& options)
{
    Stopwatch overallStopwatch;

    uint64_t callstackFrameCount = worker.GetCallstackFrameCount();
    std::string relativeSoNameMatch = "[unresolved]";

    std::cout << "* Found " << callstackFrameCount << " callstack frames. Batching into image groups..." << std::endl;
    Stopwatch batchIntoGroupsStopwatch;

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

    std::cout << "* Batched into " << entriesPerImageIdx.size()
              << " unique image groups [took: " << batchIntoGroupsStopwatch.getTimeFromStartInMs() << " ms]" << std::endl;

    struct JobEntry
    {
        FrameEntriesPerImageIdx::iterator imageIt;
        SymbolEntryList results;
        std::string imagePath;
        Stopwatch jobStopWatch;
    };

    using AllResoledEntries = std::vector<JobEntry>;
    AllResoledEntries resolvedResults;
    resolvedResults.resize( entriesPerImageIdx.size() );

    size_t index = 0;
    size_t totalEntries = 0;
    size_t processedEntries = 0;
    for( FrameEntriesPerImageIdx::iterator imageIt = entriesPerImageIdx.begin(), imageItEnd = entriesPerImageIdx.end();
         imageIt != imageItEnd; ++imageIt, ++index )
    {
        resolvedResults[index].imageIt = imageIt;
        FrameEntryList& entries = imageIt->second;
        tracy::StringIdx imageIdx( imageIt->first );
        resolvedResults[index].imagePath = worker.GetString( imageIdx );
        totalEntries += entries.size();
    }

#ifdef _WIN32
    // DbgHelper is not thread safe
    unsigned int maxConcurrent = 1;
#else
    unsigned int maxConcurrent = 
        (options.maxParallelism <= 0) ? std::thread::hardware_concurrency() : int(options.maxParallelism);
#endif

    std::cout << "* Running " << resolvedResults.size() << " resolution jobs in parallel (batches of " << maxConcurrent << ")" << std::endl;    
    Stopwatch parallelResolveStopwatch;

    // run symbol resolution for each image in parallel
    processJobsInParallel( resolvedResults.size(), maxConcurrent,

        [&resolvedResults, &worker]( size_t jobIndex )
        {
            FrameEntriesPerImageIdx::iterator imageIt = resolvedResults[jobIndex].imageIt;
            FrameEntryList& entries = imageIt->second;
            const std::string& imagePath = resolvedResults[jobIndex].imagePath;

            std::cout << "[job " << jobIndex << "/" << resolvedResults.size() << "] Starting resolving "
                      << entries.size() << " symbols for image: '" << imagePath << "' ..." << std::endl;
        },

        [&resolvedResults, &worker, &pathSubstitutionlist, skipImageList, &options]( size_t jobIndex )
        {
            std::string imagePath = resolvedResults[jobIndex].imagePath;

            if( ShouldSkipImage( imagePath, skipImageList ) )
            {
                std::cerr << " * Skipping image ' " << imagePath << "' as requested..." << std::endl;
                return;
            }

            FrameEntriesPerImageIdx::iterator imageIt = resolvedResults[jobIndex].imageIt;
            FrameEntryList& entries = imageIt->second;
            if( entries.size() )
            {
                ApplyPathSubstitutions( imagePath, pathSubstitutionlist );

                SymbolEntryList& resolvedEntries = resolvedResults[jobIndex].results;
                ResolveSymbols( imagePath, entries, resolvedEntries, options);

                if( resolvedEntries.size() != entries.size() )
                {
                    std::cerr << " failed to resolve all entries! (got: " << resolvedEntries.size()
                              << ", expected: " << entries.size() << ") discarding results ..." << std::endl;
                    resolvedEntries.clear();
                }
            }
        },
        [&resolvedResults, &worker, totalEntries, &processedEntries, &parallelResolveStopwatch]( size_t jobIndex )
        {
            FrameEntriesPerImageIdx::iterator imageIt = resolvedResults[jobIndex].imageIt;
            const size_t totalJobs = resolvedResults.size();
            const size_t entriesForJob = imageIt->second.size();
            processedEntries += entriesForJob;
            int finishedPercent = int( ( float( processedEntries ) * 100.0f ) / float( totalEntries ) );

            const std::string& imagePath = resolvedResults[jobIndex].imagePath;
            std::cout << "[job " << jobIndex << "/" << totalJobs << "] [progress: " << finishedPercent 
                      << "%, duration: " << parallelResolveStopwatch.getTimeFromStartInMs() / 1000 << " s] finished "
                      << entriesForJob << " entries for: '" << imagePath << "' in: "
                      << ( resolvedResults[jobIndex].jobStopWatch.getTimeFromStartInMs() / 1000 ) << " s" << std::endl;
        }        
    );

    std::cout << "* Parallel resolve took " << parallelResolveStopwatch.getTimeFromStartInMs() / 1000 << " s" << std::endl;
    std::cout << "* Patching resolved entries ..." << std::endl;
    Stopwatch patchingEntriesStopwatch;

    uint32_t totalEntriesAttemped = 0;
    uint32_t totalFailedResolved = 0;

    // after resolution, patch all the strings with the results. This has to be done serially unfortunately as the string manipulation 
    // in the worker is not multi thread safe!
    for( AllResoledEntries::iterator resolvedEntryit = resolvedResults.begin(), itEnd = resolvedResults.end();
         resolvedEntryit != itEnd; ++resolvedEntryit )
    {
        FrameEntriesPerImageIdx::iterator imgIt = resolvedEntryit->imageIt;
        FrameEntryList& entries = imgIt->second;
        SymbolEntryList& resolvedEntries = resolvedEntryit->results;
        tracy::StringIdx imageIdx( imgIt->first );
        std::string imagePath = worker.GetString( imageIdx );

        for( size_t i = 0; i < resolvedEntries.size(); ++i )
        {
            FrameEntry& frameEntry = entries[i];
            const SymbolEntry& symbolEntry = resolvedEntries[i];

            tracy::CallstackFrame& frame = *frameEntry.frame;

            if (!symbolEntry.resolved)
                ++totalFailedResolved;
            else
                ++totalEntriesAttemped;

            if( !symbolEntry.name.length() ) 
                continue;

            if( options.verbose )
            {
                const char* nameStr = worker.GetString( frame.name );
                std::cout << "patching '" << nameStr << "' of '" << imagePath << "' -> '" << symbolEntry.name << "'"
                        << std::endl;
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

    std::cout << "* Patching entries took " << patchingEntriesStopwatch.getTimeFromStartInMs() << " ms" << std::endl;
    size_t timeInseconds = overallStopwatch.getTimeFromStartInMs() / 1000;
    std::cout << "The whole process took  " << timeInseconds << " s" << std::endl;
    std::cout << "* Attempted resolve of " << totalEntriesAttemped 
              << " entries, failed to resolve " << totalFailedResolved 
              << "(" << (totalFailedResolved*100 / totalEntriesAttemped) << "%)" << std::endl;

    return true;
}

void PatchSymbols( tracy::Worker& worker, const std::vector<std::string>& pathSubstitutionsStrings,
                   const std::vector<std::string>& skipImageListStr, const ResolveOptions& options)
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

    SkipImageList skipImageList;
    for( const std::string& imageName : skipImageListStr )
    {
        std::cout << "Adding regex image skip: '" << imageName << "'" << std::endl;
        skipImageList.push_back( std::regex( imageName ) );
    }

    if( !PatchSymbolsWithRegex( worker, pathSubstitutionList,
                               (skipImageList.empty() ? nullptr : &skipImageList), options))
    {
        std::cerr << "Failed to patch symbols" << std::endl;
    }
}