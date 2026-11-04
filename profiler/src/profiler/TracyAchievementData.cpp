#include "TracyAchievements.hpp"
#include "TracyConfig.hpp"
#include "TracyEmbed.hpp"

#include "data/Text100Million.hpp"
#include "data/TextAddFrameSets.hpp"
#include "data/TextAllocStacks.hpp"
#include "data/TextAnnotateZones.hpp"
#include "data/TextAnnotations.hpp"
#include "data/TextAppInfo.hpp"
#include "data/TextAskAssist.hpp"
#include "data/TextCompareTraces.hpp"
#include "data/TextConnectToClient.hpp"
#include "data/TextContention.hpp"
#include "data/TextContextSwitches.hpp"
#include "data/TextCpuData.hpp"
#include "data/TextEntryStacks.hpp"
#include "data/TextFindZone.hpp"
#include "data/TextFrameImages.hpp"
#include "data/TextFrameStatistics.hpp"
#include "data/TextGhostZones.hpp"
#include "data/TextGlobalSettings.hpp"
#include "data/TextGpu.hpp"
#include "data/TextGpuStats.hpp"
#include "data/TextHwCounters.hpp"
#include "data/TextInspectZone.hpp"
#include "data/TextInstrumentFrames.hpp"
#include "data/TextInstrumentationIntro.hpp"
#include "data/TextInstrumentationStatistics.hpp"
#include "data/TextIntro.hpp"
#include "data/TextLeaks.hpp"
#include "data/TextLightFlame.hpp"
#include "data/TextLoadTrace.hpp"
#include "data/TextLocks.hpp"
#include "data/TextLogMessages.hpp"
#include "data/TextManual.hpp"
#include "data/TextMemory.hpp"
#include "data/TextMemoryPools.hpp"
#include "data/TextNameThreads.hpp"
#include "data/TextNavigate.hpp"
#include "data/TextPlots.hpp"
#include "data/TextReadAssembly.hpp"
#include "data/TextReadSource.hpp"
#include "data/TextSamplingIntro.hpp"
#include "data/TextSamplingStats.hpp"
#include "data/TextSections.hpp"
#include "data/TextSaveTrace.hpp"
#include "data/TextSurviveCrash.hpp"
#include "data/TextTimeRanges.hpp"
#include "data/TextWaitStacks.hpp"
#include "data/TextZoneCallstacks.hpp"

namespace tracy::data
{

static std::string UnpackImpl( size_t size, size_t lz4Size, const uint8_t* data )
{
    std::string ret;
    const EmbedData unembed( size, lz4Size, data );
    ret.assign( unembed.data(), unembed.size() );
    return ret;
}

#define Unpack( name ) UnpackImpl( Embed::name##Size, Embed::name##Lz4Size, Embed::name##Data )


AchievementItem ai_ghostZones = {
    .id = "ghostZones",
    .name = "Ghost zones",
    .text = Unpack( TextGhostZones )
};

AchievementItem ai_samplingStats = {
    .id = "samplingStats",
    .name = "Read sampling statistics",
    .text = Unpack( TextSamplingStats )
};

AchievementItem ai_entryStacks = {
    .id = "entryStacks",
    .name = "Open entry stacks",
    .text = Unpack( TextEntryStacks )
};

AchievementItem ai_waitStacks = {
    .id = "waitStacks",
    .name = "Read wait stacks",
    .text = Unpack( TextWaitStacks )
};

AchievementItem* ac_contextSwitchesItems[] = { &ai_waitStacks, nullptr };

AchievementItem ai_contextSwitches = {
    .id = "contextSwitches",
    .name = "See the whole machine",
    .text = Unpack( TextContextSwitches ),
    .items = ac_contextSwitchesItems
};

AchievementItem ai_cpuData = {
    .id = "cpuData",
    .name = "See every process that ran",
    .text = Unpack( TextCpuData )
};

AchievementItem* ac_samplingIntroItems[] = { &ai_ghostZones, &ai_samplingStats, &ai_entryStacks, &ai_contextSwitches, &ai_cpuData, nullptr };

AchievementItem ai_samplingIntro = {
    .id = "samplingIntro",
    .name = "Sampling program execution",
    .text = Unpack( TextSamplingIntro ),
    .items = ac_samplingIntroItems,
};

AchievementItem* ac_samplingItems[] = { &ai_samplingIntro, nullptr };
AchievementCategory ac_sampling = { "sampling", "Sampling", ac_samplingItems };

AchievementItem ai_huntLeaks = {
    .id = "huntLeaks",
    .name = "Hunt leaks",
    .text = Unpack( TextLeaks )
};

AchievementItem ai_allocStacks = {
    .id = "allocStacks",
    .name = "Trace allocation call stacks",
    .text = Unpack( TextAllocStacks )
};

AchievementItem ai_memoryPools = {
    .id = "memoryPools",
    .name = "Separate pools",
    .text = Unpack( TextMemoryPools )
};

AchievementItem* ac_trackMemoryItems[] = { &ai_huntLeaks, &ai_allocStacks, &ai_memoryPools, nullptr };

AchievementItem ai_trackMemory = {
    .id = "trackMemory",
    .name = "Track memory",
    .text = Unpack( TextMemory ),
    .items = ac_trackMemoryItems
};

AchievementItem* ac_memoryItems[] = { &ai_trackMemory, nullptr };
AchievementCategory ac_memory = { "memory", "Memory", ac_memoryItems };

AchievementItem ai_gpuStats = {
    .id = "gpuStats",
    .name = "GPU statistics",
    .text = Unpack( TextGpuStats )
};

AchievementItem* ac_profileGpuItems[] = { &ai_gpuStats, nullptr };
AchievementItem ai_profileGpu = {
    .id = "profileGpu",
    .name = "Profile the GPU",
    .text = Unpack( TextGpu ),
    .items = ac_profileGpuItems
};

AchievementItem* ac_gpuItems[] = { &ai_profileGpu, nullptr };
AchievementCategory ac_gpu = { "gpu", "GPU", ac_gpuItems };

AchievementItem ai_lockContention = {
    .id = "lockContention",
    .name = "Analyze contention",
    .text = Unpack( TextContention )
};

AchievementItem* ac_watchLocksItems[] = { &ai_lockContention, nullptr };

AchievementItem ai_watchLocks = {
    .id = "watchLocks",
    .name = "Watch locks",
    .text = Unpack( TextLocks ),
    .items = ac_watchLocksItems
};

AchievementItem* ac_locksItems[] = { &ai_watchLocks, nullptr };
AchievementCategory ac_locks = { "locks", "Locks", ac_locksItems };


AchievementItem ai_100million = {
    .id = "100million",
    .name = "It's over 100 million!",
    .text = Unpack( Text100Million )
};

AchievementItem ai_instrumentationStatistics = {
    .id = "instrumentationStatistics",
    .name = "Show me the stats!",
    .text = Unpack( TextInstrumentationStatistics )
};

AchievementItem ai_findZone = {
    .id = "findZone",
    .name = "Find some zones",
    .text = Unpack( TextFindZone )
};

AchievementItem ai_hwCounters = {
    .id = "hwCounters",
    .name = "Hardware counters",
    .text = Unpack( TextHwCounters )
};

AchievementItem* ac_readAssemblyItems[] = { &ai_hwCounters, nullptr };

AchievementItem ai_readAssembly = {
    .id = "readAssembly",
    .name = "Assembly required",
    .text = Unpack( TextReadAssembly ),
    .items = ac_readAssemblyItems
};

AchievementItem ai_compareTraces = {
    .id = "compareTraces",
    .name = "Compare traces",
    .text = Unpack( TextCompareTraces )
};

AchievementItem* ac_readSourceItems[] = { &ai_readAssembly, nullptr };

AchievementItem ai_readSource = {
    .id = "readSource",
    .name = "Read the source",
    .text = Unpack( TextReadSource ),
    .items = ac_readSourceItems
};

AchievementItem ai_annotations = {
    .id = "annotations",
    .name = "Annotate the timeline",
    .text = Unpack( TextAnnotations )
};

AchievementItem* ac_timeRangesItems[] = { &ai_annotations, nullptr };

AchievementItem ai_timeRanges = {
    .id = "timeRanges",
    .name = "Set a time range",
    .text = Unpack( TextTimeRanges ),
    .items = ac_timeRangesItems
};

AchievementItem ai_lightFlame = {
    .id = "lightFlame",
    .name = "Light the flame",
    .text = Unpack( TextLightFlame )
};

AchievementItem ai_frameStats = {
    .id = "frameStats",
    .name = "Frame statistics",
    .text = Unpack( TextFrameStatistics )
};

AchievementItem ai_surviveCrash = {
    .id = "surviveCrash",
    .name = "Survive a crash",
    .text = Unpack( TextSurviveCrash )
};

AchievementItem ai_askAssist = {
    .id = "askAssist",
    .name = "Ask Tracy Assist",
    .text = Unpack( TextAskAssist ),
    .visible = [] { return s_config.llm; }
};

AchievementItem* ac_inspectZoneItems[] = { &ai_findZone, &ai_readSource, &ai_lightFlame, nullptr };

AchievementItem ai_inspectZone = {
    .id = "inspectZone",
    .name = "Inspect a zone",
    .text = Unpack( TextInspectZone ),
    .items = ac_inspectZoneItems
};

AchievementItem* ac_analysisItems[] = { &ai_inspectZone, &ai_frameStats, &ai_surviveCrash, &ai_askAssist, &ai_timeRanges, &ai_compareTraces, nullptr };
AchievementCategory ac_analysis = { "analysis", "Analysis", ac_analysisItems };

AchievementItem ai_annotateZones = {
    .id = "annotateZones",
    .name = "Annotate zones",
    .text = Unpack( TextAnnotateZones )
};

AchievementItem ai_markSections = {
    .id = "markSections",
    .name = "Mark sections",
    .text = Unpack( TextSections )
};

AchievementItem ai_chartValues = {
    .id = "chartValues",
    .name = "Chart values",
    .text = Unpack( TextPlots )
};

AchievementItem ai_logMessages = {
    .id = "logMessages",
    .name = "Log messages",
    .text = Unpack( TextLogMessages )
};

AchievementItem ai_zoneCallstacks = {
    .id = "zoneCallstacks",
    .name = "Capture zone call stacks",
    .text = Unpack( TextZoneCallstacks )
};

AchievementItem* ac_instrumentationIntroItems[] = {
    &ai_instrumentationStatistics,
    &ai_annotateZones,
    &ai_markSections,
    &ai_zoneCallstacks,
    &ai_100million,
    nullptr
};

AchievementItem* ac_instrumentationIntroUnlock[] = { &ai_trackMemory, &ai_profileGpu, &ai_watchLocks, &ai_inspectZone, nullptr };

AchievementItem ai_instrumentationIntro = {
    .id = "instrumentationIntro",
    .name = "Instrumenting your application",
    .text = Unpack( TextInstrumentationIntro ),
    .items = ac_instrumentationIntroItems,
    .unlocks = ac_instrumentationIntroUnlock
};

AchievementItem ai_frameImages = {
    .id = "frameImages",
    .name = "A picture is worth a thousand words",
    .text = Unpack( TextFrameImages )
};

AchievementItem* ac_addFrameSetsUnlock[] = { &ai_frameStats, nullptr };

AchievementItem ai_addFrameSets = {
    .id = "addFrameSets",
    .name = "Add frame sets",
    .text = Unpack( TextAddFrameSets ),
    .unlocks = ac_addFrameSetsUnlock
};

AchievementItem* ac_instrumentFramesItems[] = {
    &ai_frameImages,
    &ai_addFrameSets,
    nullptr
};

AchievementItem ai_instrumentFrames = {
    .id = "instrumentFrames",
    .name = "Instrumenting frames",
    .text = Unpack( TextInstrumentFrames ),
    .items = ac_instrumentFramesItems
};

AchievementItem* ac_instrumentationItems[] = { &ai_instrumentationIntro, &ai_chartValues, &ai_logMessages, &ai_instrumentFrames, nullptr };
AchievementCategory ac_instrumentation = { "instrumentation", "Instrumentation", ac_instrumentationItems };


AchievementItem ai_loadTrace = {
    .id = "loadTrace",
    .name = "Load a trace",
    .text = Unpack( TextLoadTrace )
};

AchievementItem ai_saveTrace = {
    .id = "saveTrace",
    .name = "Save a trace",
    .text = Unpack( TextSaveTrace )
};

AchievementItem ai_appInfo = {
    .id = "appInfo",
    .name = "Describe your application",
    .text = Unpack( TextAppInfo )
};

AchievementItem ai_nameThreads = {
    .id = "nameThreads",
    .name = "Name your threads",
    .text = Unpack( TextNameThreads )
};

AchievementItem ai_navigate = {
    .id = "navigate",
    .name = "Navigating the view",
    .text = Unpack( TextNavigate )
};

AchievementItem* ac_connectToServerItems[] = {
    &ai_navigate,
    &ai_appInfo,
    &ai_nameThreads,
    &ai_saveTrace,
    &ai_loadTrace,
    nullptr
};

AchievementItem* ac_connectToServerUnlock[] = {
    &ai_instrumentationIntro,
    &ai_samplingIntro,
    nullptr
};

AchievementItem ai_connectToServer = {
    .id = "connectToClient",
    .name = "First profiling session",
    .text = Unpack( TextConnectToClient ),
    .items = ac_connectToServerItems,
    .unlocks = ac_connectToServerUnlock
};

AchievementItem ai_globalSettings = {
    .id = "globalSettings",
    .name = "Global settings",
    .text = Unpack( TextGlobalSettings )
};

AchievementItem ai_manual = {
    .id = "manual",
    .name = "Read the manual",
    .text = Unpack( TextManual )
};

AchievementItem* ac_achievementsIntroItems[] = {
    &ai_connectToServer,
    &ai_globalSettings,
    &ai_manual,
    nullptr
};

AchievementItem ai_achievementsIntro = {
    .id = "achievementsIntro",
    .name = "Click here to discover achievements!",
    .text = Unpack( TextIntro ),
    .items = ac_achievementsIntroItems,
    .keepOpen = true,
    .unlockTime = 1
};

AchievementItem* ac_firstStepsItems[] = { &ai_achievementsIntro, nullptr };
AchievementCategory ac_firstSteps = { "firstSteps", "First steps", ac_firstStepsItems, 1 };


AchievementCategory* AchievementCategories[] = {
    &ac_firstSteps,
    &ac_instrumentation,
    &ac_sampling,
    &ac_memory,
    &ac_gpu,
    &ac_locks,
    &ac_analysis,
    nullptr
};

}
