#include "IconsFontAwesome6.h"
#include "TracyAchievements.hpp"
#include "TracyImGui.hpp"
#include "TracySourceContents.hpp"
#include "TracyWeb.hpp"

namespace tracy::data
{

AchievementItem ai_instrumentationIntro = { "instrumentationIntro", "Instrumentation", [](const ctx& c){
    constexpr const char* src = R"(#include "Tracy.hpp"

void SomeFunction()
{
    ZoneScoped;
    // Your code here
}
)";

    static SourceContents sc;
    sc.Parse( src );
    
    ImGui::TextWrapped( "Instrumentation is a powerful feature that allows you to see the exact runtime of each call to the selected set of functions. The downside is that it takes a bit of manual work to get it set up." );
    ImGui::TextWrapped( "To get started, open a source file and include the Tracy.hpp header. This will give you access to a variety of macros provided by Tracy. Next, add the ZoneScoped macro to the beginning of one of your functions, like this:" );
    ImGui::PushFont( c.fixed );
    PrintSource( sc.get() );
    ImGui::PopFont();
    ImGui::TextWrapped( "Now, when you profile your application, you will see a new zone appear on the timeline for each call to the function. This allows you to see how much time is spent in each call and how many times the function is called." );
    ImGui::PushFont( c.small );
    ImGui::PushStyleColor( ImGuiCol_Text, 0xFF888888 );
    ImGui::TextWrapped( "Note: The ZoneScoped macro is just one of the many macros provided by Tracy. See the documentation for more information." );
    ImGui::TextWrapped( "The above description applies to C++ code, but things are done similarly in other programming languages. Refer to the documentation for your language for more information." );
    ImGui::PopStyleColor();
    ImGui::PopFont();
} };

AchievementItem* ac_instrumentationItems[] = { &ai_instrumentationIntro, nullptr };
AchievementCategory ac_instrumentation = { "instrumentation", "Instrumentation", ac_instrumentationItems };


AchievementItem ai_loadTrace = { "loadTrace", "Load a trace", [](const ctx&){
    ImGui::TextWrapped( "You can open a previously saved trace file (or one received from a friend) with the '" ICON_FA_FOLDER_OPEN " Open saved trace' button on the welcome screen." );
} };

AchievementItem ai_saveTrace = { "saveTrace", "Save a trace", [](const ctx&){
    ImGui::TextWrapped( "Now that you have traced your application (or are in the process of doing so), you can save it to disk for future reference. You can do this by clicking on the " ICON_FA_WIFI " icon in the top left corner of the screen and then clicking on the '" ICON_FA_FLOPPY_DISK " Save trace' button." );
    ImGui::TextWrapped( "Keeping old traces on hand can be beneficial, as you can compare the performance of your optimizations with what you had before." );
    ImGui::TextWrapped( "You can also share the trace with your friends or co-workers by sending them the trace file." );
    ImGui::Spacing();
    tracy::TextColoredUnformatted( 0xFF44FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
    ImGui::SameLine();
    ImGui::TextUnformatted( "Warning" );
    ImGui::SameLine();
    tracy::TextColoredUnformatted( 0xFF44FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
    ImGui::TextWrapped( "Trace files can contain sensitive information about your application, such as program code, or even the contents of source files. Be careful when sharing them with others." );
} };

AchievementItem* ac_connectToServerItems[] = {
    &ai_saveTrace,
    &ai_loadTrace,
    nullptr
};

AchievementItem ai_connectToServer = { "connectToClient", "First profiling session", [](const ctx&){
    ImGui::TextWrapped( "Let's start our adventure by instrumenting your application and connecting it to the profiler. Here's a quick refresher:" );
    ImGui::TextWrapped( " 1. Integrate Tracy Profiler into your application. This can be done using CMake, Meson, or simply by adding the source files to your project." );
    ImGui::TextWrapped( " 2. Make sure that TracyClient.cpp (or the Tracy library) is included in your build." );
    ImGui::TextWrapped( " 3. Define TRACY_ENABLE in your build configuration, for the whole application. Do not do it in a single source file because it won't work." );
    ImGui::TextWrapped( " 4. Start your application, and '" ICON_FA_WIFI " Connect' to it with the profiler." );
    ImGui::TextWrapped( "Please refer to the user manual for more details." );
    if( ImGui::SmallButton( "Download the user manual" ) )
    {
        tracy::OpenWebpage( "https://github.com/wolfpld/tracy/releases" );
    }
}, ac_connectToServerItems, ac_instrumentationItems };

AchievementItem* ac_achievementsIntroItems[] = {
    &ai_connectToServer,
    nullptr
};

AchievementItem ai_achievementsIntro = { "achievementsIntro", "Click here to discover achievements!", [](const ctx&){
    ImGui::TextWrapped( "Clicking on the " ICON_FA_STAR " button opens the Achievements List. Here you can see the tasks to be completed along with a short description of what needs to be done." );
    ImGui::TextWrapped( "As you complete each Achievement, new Achievements will appear, so be sure to keep checking the list for new ones!" );
    ImGui::TextWrapped( "To make the new things easier to spot, the Achievements List will show a marker next to them. The achievements " ICON_FA_STAR " button will glow yellow when there are new things to see." );
    ImGui::TextUnformatted( "New tasks:" );
    ImGui::SameLine();
    TextColoredUnformatted( 0xFF4488FF, ICON_FA_CIRCLE_EXCLAMATION );
    ImGui::TextUnformatted( "Completed tasks:" );
    ImGui::SameLine();
    TextColoredUnformatted( 0xFF44FF44, ICON_FA_CIRCLE_CHECK );
    ImGui::TextWrapped( "Good luck!" );
}, ac_achievementsIntroItems, nullptr, true, 1 };

AchievementItem* ac_firstStepsItems[] = { &ai_achievementsIntro, nullptr };
AchievementCategory ac_firstSteps = { "firstSteps", "First steps", ac_firstStepsItems, 1 };


AchievementCategory* AchievementCategories[] = {
    &ac_firstSteps,
    &ac_instrumentation,
    nullptr
};

}
