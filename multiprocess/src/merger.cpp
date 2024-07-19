#include "TracyFileRead.hpp"
#include "TracyFileWrite.hpp"
#include "TracyWorker.hpp"
#include "getopt.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std::chrono_literals;

bool orderImportTimelineEvents(tracy::Worker::ImportEventTimeline const& a, tracy::Worker::ImportEventTimeline const& b)
{
    return a.timestamp < b.timestamp;
}

bool orderImportMessageEvents(tracy::Worker::ImportEventMessages const& a, tracy::Worker::ImportEventMessages const& b)
{
    return a.timestamp < b.timestamp;
}

struct ExportedWorker
{
    std::vector<tracy::Worker::ImportEventTimeline> timeline;
    std::vector<tracy::Worker::ImportEventMessages> messages;
    std::vector<tracy::Worker::ImportEventPlots> plots;

    std::unordered_map<uint64_t, std::string> threadNames;
    std::string name;
    std::string process;

    static ExportedWorker merge(std::vector<ExportedWorker const*> inputList)
    {
        uint64_t nextFreeThreadId = 1;
        ExportedWorker out;

        // for some data, arbitrarily take the infos from the first trace
        auto const& firstExport = *inputList[0];
        out.name                = firstExport.name;
        out.process             = firstExport.process;

        // quick pass to allocate output vectors
        size_t numTimelineEvents = 0, numMessages = 0, numPlots = 0;
        for (auto const& inputWorker : inputList)
        {
            numTimelineEvents += inputWorker->timeline.size();
            numMessages += inputWorker->messages.size();
            numPlots += inputWorker->plots.size();
        }
        out.timeline.reserve(numTimelineEvents);
        out.messages.reserve(numMessages);
        out.plots.reserve(numPlots);

        size_t eventsSortedSoFar   = 0;
        size_t messagesSortedSoFar = 0;

        // keep track of registered threads to avoid overlaps
        std::unordered_map<uint64_t, uint64_t> localThreadToMultiprocess;

        for (auto exportPtr : inputList)
        {
            ExportedWorker const& exported = *exportPtr;

            // rebuild thread mapping
            // we try to keep original thread IDs intact if possible, falling back to made-up IDs
            // in case of conflict
            for (auto const& threadId : exported.threadNames)
            {
                uint64_t multiprocessId = threadId.first;
                if (localThreadToMultiprocess.contains(multiprocessId))
                {
                    // oh-oh, conflict - let's take a random ID instead;
                    multiprocessId = nextFreeThreadId++;
                }
                localThreadToMultiprocess[threadId.first] = multiprocessId;
                out.threadNames[multiprocessId]           = threadId.second;
            }

            // translate all events with the right thread IDs
            for (auto&& event : exported.timeline)
            {
                tracy::Worker::ImportEventTimeline& inserted = out.timeline.emplace_back(event);
                inserted.tid                                 = localThreadToMultiprocess[inserted.tid];
            }
            for (auto&& message : exported.messages)
            {
                tracy::Worker::ImportEventMessages& inserted = out.messages.emplace_back(message);
                inserted.tid                                 = localThreadToMultiprocess[inserted.tid];
            }
            for (auto&& plots : exported.plots)
            {
                out.plots.emplace_back(plots);
            }

            // sort timeline and messages events
            std::inplace_merge(out.timeline.begin(),
                               out.timeline.begin() + eventsSortedSoFar,
                               out.timeline.end(),
                               orderImportTimelineEvents);
            eventsSortedSoFar += exported.timeline.size();
            std::inplace_merge(out.messages.begin(),
                               out.messages.begin() + messagesSortedSoFar,
                               out.messages.end(),
                               orderImportMessageEvents);
            messagesSortedSoFar += exported.messages.size();
        }
        return out;
    }



    static std::optional<ExportedWorker> fromTracyFile(std::string const& filepath, bool exportPlots)
    {
        std::unique_ptr<tracy::FileRead> sourceFile{tracy::FileRead::Open((filepath.c_str()))};
        if (!sourceFile)
        {
            std::cerr << "Could not find file" << std::endl;
            return std::nullopt;
        }
        std::cout << "reading " << filepath << std::endl;

        tracy::Worker worker{*sourceFile,
                             tracy::EventType::All,
                             true,  // otherwise source zones are empty
                             false};
        while (!worker.AreSourceLocationZonesReady())
        {
            std::cout << "Waiting for source locations" << std::endl;
            std::this_thread::sleep_for(1s);
        }

        ExportedWorker exportedData;
        exportedData.name    = worker.GetCaptureName();
        exportedData.process = worker.GetCaptureProgram();
        std::cout << exportedData.name << " (" << exportedData.process << ")" << std::endl;

        std::unordered_set<uint64_t> seenThreadIds;

        auto& sourceLocationZones = worker.GetSourceLocationZones();
        std::cout << "- " << sourceLocationZones.size() << " events" << std::endl;
        for (auto&& zone_it : sourceLocationZones)
        {
            const tracy::SourceLocation& sourceLoc = worker.GetSourceLocation(zone_it.first);
            std::string zoneFilePath               = worker.GetString(sourceLoc.file);
            int zoneLine                           = sourceLoc.line;
            std::string zoneName                   = worker.GetZoneName(sourceLoc);

            auto const& zones = zone_it.second;
            for (auto&& zoneData : zones.zones)
            {
                const auto zone_event       = zoneData.Zone();
                const uint64_t threadFullId = worker.DecompressThread(zoneData.Thread());
                const auto start            = zone_event->Start();
                const auto end              = zone_event->End();
                seenThreadIds.emplace(threadFullId);

                auto& startEvent     = exportedData.timeline.emplace_back();
                startEvent.locFile   = zoneFilePath;
                startEvent.locLine   = zoneLine;
                startEvent.name      = zoneName;
                startEvent.tid       = threadFullId;
                startEvent.isEnd     = false;
                startEvent.timestamp = zone_event->Start();

                auto& endEvent     = exportedData.timeline.emplace_back();
                endEvent.locFile   = zoneFilePath;
                endEvent.locLine   = zoneLine;
                endEvent.name      = zoneName;
                endEvent.tid       = threadFullId;
                endEvent.isEnd     = true;
                endEvent.timestamp = zone_event->End();
            }
        }
        // need to sort because we split 'begin' and 'end' events
        std::sort(exportedData.timeline.begin(), exportedData.timeline.end(), orderImportTimelineEvents);

        auto const& messages = worker.GetMessages();
        std::cout << "- " << messages.size() << " messages" << std::endl;
        for (auto const& messages_it : worker.GetMessages())
        {
            tracy::MessageData const& messageData = *messages_it;
            tracy::Worker::ImportEventMessages importMessage;
            uint64_t const threadId = worker.DecompressThread(messageData.thread);
            importMessage.tid       = threadId;
            importMessage.message   = worker.GetString(messageData.ref);
            importMessage.timestamp = messageData.time;

            exportedData.messages.push_back(importMessage);
            seenThreadIds.emplace(threadId);
        }
        // to be sure, but should not do a lot
        std::sort(exportedData.messages.begin(), exportedData.messages.end(), orderImportMessageEvents);

        if (exportPlots)
        {
            auto const& plots = worker.GetPlots();
            std::cout << "- " << plots.size() << " plots" << std::endl;
            for (auto const& plots_it : worker.GetPlots())
            {
                tracy::Worker::ImportEventPlots importPlot;
                importPlot.name   = worker.GetString(plots_it->name);
                importPlot.format = plots_it->format;

                importPlot.data.resize(plots_it->data.size());
                for (auto const& elt : plots_it->data)
                {
                    std::pair<int64_t, double> dataPoint{elt.time.Val(), elt.val};
                    importPlot.data.push_back(dataPoint);
                }
                exportedData.plots.push_back(importPlot);
            }
        }

        for (auto&& tid : seenThreadIds)
        {
            std::string name              = worker.GetThreadName(tid);
            exportedData.threadNames[tid] = exportedData.process + "/" + name;
        }

        return exportedData;
    }
};


[[noreturn]] void Usage()
{
    printf("Usage: merge [-fp] -o output.tracy input1.tracy [input2.tracy]...\n\n");
    printf("Options\n");
    printf("  --output/-o <filepath>    Output file path\n");
    printf("  --force/-f                Overwrite output file if it exists\n");
    printf("  --export-plots/-p         (experimental) Also exports plots\n");
    exit(1);
}

struct Args
{
    std::vector<std::string> inputPaths;
    std::string outputPath;
    bool exportPlots=false;

    static Args parse(int argc, char* argv[])
    {
        Args args;
        // option parsing
        bool overwrite = false;
        int c;
        const struct option long_options[] = {
            { "output", required_argument, 0, 'o' },
            { "force", no_argument, 0, 'f' },
            { "export-plots", no_argument, 0, 'p' },
            { 0, 0, 0, 0 },
        };
        while( ( c = getopt_long( argc, argv, "o:fp", long_options, nullptr ) ) != -1 )
        {
            switch( c )
            {
            case 'o':
                args.outputPath = optarg;
                break;
            case 'f':
                overwrite = true;
                break;
            case 'p':
                args.exportPlots = true;
                break;
            default:
                Usage();
                break;
            }
        }
        for (int argIndex = optind; argIndex < argc; argIndex++)
        {
            args.inputPaths.push_back(argv[argIndex]);
        }
        if (args.inputPaths.size() == 0 or args.outputPath.empty())
        {
            Usage();
        }
        if (std::filesystem::exists(args.outputPath) and not overwrite)
        {
            printf("Output file %s already exists! Use -f to force overwrite.\n", args.outputPath.c_str());
            exit(4);
        }
        for (auto const& input : args.inputPaths)
        {
            if (not std::filesystem::exists(input))
            {
                printf("Input file %s does not exist!\n", input.c_str());
                exit(4);
            }
        }
        return args;
    }
};

int main(int argc, char* argv[])
{
    auto args = Args::parse(argc, argv);

    std::vector<ExportedWorker> exports;
    for (auto path : args.inputPaths)
    {
        auto importedOpt = ExportedWorker::fromTracyFile(path, args.exportPlots);
        if (not importedOpt.has_value())
        {
            std::cerr << "Error importing " << path << std::endl;
            return 1;
        }
        exports.push_back((importedOpt.value()));
    }

    std::vector<ExportedWorker const*> exportRefs;
    std::transform(
        exports.cbegin(), exports.cend(), std::back_inserter(exportRefs), [](ExportedWorker const& ex) { return &ex; });

    auto mergedImport = ExportedWorker::merge(exportRefs);

    {
        std::cout << "Writing " << args.outputPath << std::endl;
        auto outputFileWrite = std::unique_ptr<tracy::FileWrite>(tracy::FileWrite::Open(args.outputPath.c_str()));
        if (!outputFileWrite)
        {
            fprintf(stderr, "Cannot open output file!\n");
            exit(1);
        }
        tracy::Worker outputWorker(mergedImport.name.c_str(),
                                   mergedImport.process.c_str(),
                                   mergedImport.timeline,
                                   mergedImport.messages,
                                   mergedImport.plots,
                                   mergedImport.threadNames);
        outputWorker.Write(*outputFileWrite, false);
        outputFileWrite->Finish();
    }

    std::cout << "done" << std::endl;

    return 0;
}
