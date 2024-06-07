#include "IconsFontAwesome6.h"
#include "TracyAchievements.hpp"
#include "TracyImGui.hpp"
#include "TracyWeb.hpp"

namespace tracy::data
{

AchievementItem ai_connectToServer = { "connectToClient", "First profiling session", [](const ctx&){
    ImGui::TextWrapped( "Let's start our adventure by instrumenting your application and connecting it to the profiler. Here's a quick refresher:" );
    ImGui::TextWrapped( " 1. Integrate Tracy Profiler into your application. This can be done using CMake, Meson, or simply by adding the source files to your project." );
    ImGui::TextWrapped( " 2. Make sure that TracyClient.cpp (or the Tracy library) is included in your build." );
    ImGui::TextWrapped( " 3. Define TRACY_ENABLE in your build configuration, for the whole application. Do not do it in a single source file because it won't work." );
    ImGui::TextWrapped( " 4. Start your application, and connect to it with the profiler." );
    ImGui::TextWrapped( "Please refer to the user manual for more details." );
    if( ImGui::SmallButton( "Download the user manual" ) )
    {
        tracy::OpenWebpage( "https://github.com/wolfpld/tracy/releases" );
    }
} };

AchievementItem* ac_achievementsIntroItems[] = {
    &ai_connectToServer,
    nullptr
};

AchievementItem ai_achievementsIntro = { "achievementsIntro", "Click here to discover achievements!", [](const ctx&){
    ImGui::TextWrapped( "Clicking on the " ICON_FA_STAR " button opens the Achievements List. Here you can see the tasks to be completed along with a short description of what needs to be done." );
    ImGui::TextWrapped( "As you complete each Achievement, new Achievements will appear, so be sure to keep checking the list for new ones!" );
    ImGui::TextUnformatted( "New tasks:" );
    ImGui::SameLine();
    TextColoredUnformatted( 0xFF4488FF, ICON_FA_CIRCLE_EXCLAMATION );
    ImGui::TextUnformatted( "Completed tasks:" );
    ImGui::SameLine();
    TextColoredUnformatted( 0xFF44FF44, ICON_FA_CIRCLE_CHECK );
    ImGui::TextWrapped( "Good luck!" );
}, ac_achievementsIntroItems, true, 1 };

AchievementItem* ac_firstStepsItems[] = { &ai_achievementsIntro, nullptr };
AchievementCategory ac_firstSteps = { "firstSteps", "First steps", ac_firstStepsItems, 1 };

AchievementCategory* AchievementCategories[] = { &ac_firstSteps, nullptr };

}
