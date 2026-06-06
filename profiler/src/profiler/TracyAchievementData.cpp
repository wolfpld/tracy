#include "TracyAchievements.hpp"
#include "TracyEmbed.hpp"

#include "data/Text100Million.hpp"
#include "data/TextConnectToClient.hpp"
#include "data/TextFindZone.hpp"
#include "data/TextFrameImages.hpp"
#include "data/TextGlobalSettings.hpp"
#include "data/TextInstrumentFrames.hpp"
#include "data/TextInstrumentationIntro.hpp"
#include "data/TextInstrumentationStatistics.hpp"
#include "data/TextIntro.hpp"
#include "data/TextLoadTrace.hpp"
#include "data/TextSamplingIntro.hpp"
#include "data/TextSaveTrace.hpp"

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


AchievementItem ai_samplingIntro = {
    .id = "samplingIntro",
    .name = "Sampling program execution",
    .text = Unpack( TextSamplingIntro ),
};

AchievementItem* ac_samplingItems[] = { &ai_samplingIntro, nullptr };
AchievementCategory ac_sampling = { "sampling", "Sampling", ac_samplingItems };


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

AchievementItem* ac_instrumentationIntroItems[] = {
    &ai_100million,
    &ai_instrumentationStatistics,
    &ai_findZone,
    nullptr
};

AchievementItem ai_instrumentationIntro = {
    .id = "instrumentationIntro",
    .name = "Instrumentating your application",
    .text = Unpack( TextInstrumentationIntro ),
    .items = ac_instrumentationIntroItems
};

AchievementItem ai_frameImages = {
    .id = "frameImages",
    .name = "A picture is worth a thousand words",
    .text = Unpack( TextFrameImages )
};

AchievementItem* ac_instrumentFramesItems[] = {
    &ai_frameImages,
    nullptr
};

AchievementItem ai_instrumentFrames = {
    .id = "instrumentFrames",
    .name = "Instrumenting frames",
    .text = Unpack( TextInstrumentFrames ),
    .items = ac_instrumentFramesItems
};

AchievementItem* ac_instrumentationItems[] = { &ai_instrumentationIntro, &ai_instrumentFrames, nullptr };
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

AchievementItem* ac_connectToServerItems[] = {
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

AchievementItem* ac_achievementsIntroItems[] = {
    &ai_connectToServer,
    &ai_globalSettings,
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
    nullptr
};

}
