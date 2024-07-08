#include "IconsFontAwesome6.h"
#include "TracyAchievements.hpp"
#include "TracyImGui.hpp"
#include "TracySourceContents.hpp"
#include "TracyWeb.hpp"

namespace tracy::data
{

AchievementItem ai_samplingIntro = { "samplingIntro", "Sampling program execution", [](const ctx& c){
    ImGui::TextWrapped( "Sampling program execution is a great way to find out where the hot spots are in your program. It can be used to find out which functions take the most time, or which lines of code are executed the most often." );
    ImGui::TextWrapped( "While instrumentation requires changes to your code, sampling does not. However, because of the way it works, the results are coarser and it's not possible to know when functions are called or when they return." );
    ImGui::TextWrapped( "Sampling is automatic on Linux. On Windows, you must run the profiled application as an administrator for it to work." );
    ImGui::PushFont( c.small );
    ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
    ImGui::TextWrapped( "Depending on your system configuration, some additional steps may be required. Please refer to the user manual for more information." );
    ImGui::PopStyleColor();
    ImGui::PopFont();
} };

AchievementItem* ac_samplingItems[] = { &ai_samplingIntro, nullptr };
AchievementCategory ac_sampling = { "sampling", "Sampling", ac_samplingItems };


AchievementItem ai_100million = { "100million", "It's over 100 million!", [](const ctx& c){
    ImGui::TextWrapped( "Tracy can handle a lot of data. How about 100 million zones in a single trace? Add a lot of zones to your program and see how it handles it!" );
    ImGui::TextWrapped( "Capturing a long-running profile trace is easy. Need to profile an hour of your program execution? You can do it." );
    ImGui::TextWrapped( "Note that it doesn't make much sense to instrument every little function you might have. The cost of the instrumentation itself will be higher than the cost of the function in such a case." );
    ImGui::PushFont( c.small );
    ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
    ImGui::TextWrapped( "Keep in mind that the more zones you have, the more memory and CPU time the profiler will use. Be careful not to run out of memory." );
    ImGui::TextWrapped( "To capture 100 million zones, you will need approximately 4 GB of RAM." );
    ImGui::PopStyleColor();
    ImGui::PopFont();
} };

AchievementItem ai_instrumentationStatistics = { "instrumentationStatistics", "Show me the stats!", [](const ctx&){
    ImGui::TextWrapped( "Once you have instrumented your application, you can view the statistics for each zone in the timeline. This allows you to see how much time is spent in each zone and how many times it is called." );
    ImGui::TextWrapped( "To view the statistics, click on the \"" ICON_FA_ARROW_UP_WIDE_SHORT " Statistics\" button on the top bar. This will open a new window with a list of all zones in the trace." );
} };

AchievementItem ai_findZone = { "findZone", "Find some zones", [](const ctx&){
    ImGui::TextWrapped( "You can search for zones in the trace by opening the search window with the \"" ICON_FA_MAGNIFYING_GLASS " Find zone\" button on the top bar. It will ask you for the zone name, which in most cases will be the function name in the code." );
    ImGui::TextWrapped( "The search may find more than one zone with the same name. A list of all the zones found is displayed, and you can select any of them." );
    ImGui::TextWrapped( "Alternatively, you can open the Statistics window and click an entry there. This will open the Find zone window as if you had searched for that zone." );
    ImGui::TextWrapped( "When a zone is selected, a number of statistics are displayed to help you understand the performance of your application. In addition, a histogram of the zone execution times is displayed to make it easier for you to determine the performance of the profiled code. Be sure to select a zone with a large number of calls to make the histogram look interesting!" );
    ImGui::TextWrapped( "Note that you can draw a range on the histogram to limit the number of entries displayed in the zone list below. This list allows you to examine each zone individually. There are also a number of zone groupings that you can select. Each group can be selected and the time associated with the selected group will be highlighted on the histogram." );
} };

AchievementItem* ac_instrumentationIntroItems[] = {
    &ai_100million,
    &ai_instrumentationStatistics,
    &ai_findZone,
    nullptr
};

AchievementItem ai_instrumentationIntro = { "instrumentationIntro", "Instrumentating your application", [](const ctx& c){
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
    ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
    ImGui::TextWrapped( "Note: The ZoneScoped macro is just one of the many macros provided by Tracy. See the documentation for more information." );
    ImGui::TextWrapped( "The above description applies to C++ code, but things are done similarly in other programming languages. Refer to the documentation for your language for more information." );
    ImGui::PopStyleColor();
    ImGui::PopFont();
}, ac_instrumentationIntroItems };

AchievementItem ai_frameImages = { "frameImages", "A picture is worth a thousand words", [](const ctx&){
    ImGui::TextWrapped( "Tracy allows you to add context to each frame, by attaching a screenshot. You can do this with the FrameImage macro." );
    ImGui::TextWrapped( "You will have to do the screen capture and resizing yourself, which can be a bit complicated. The manual provides a sample code that shows how to do this in a performant way." );
    ImGui::TextWrapped( "The frame images are displayed in the context of a frame, for example, when you hover over the frame in the timeline or in the frame graph at the top of the screen." );
    ImGui::TextWrapped( "You can even view a recording of what your application was doing by clicking the " ICON_FA_SCREWDRIVER_WRENCH " icon and then selecting the \"" ICON_FA_PLAY " Playback\" option. Try it out!" );
    ImGui::TextWrapped( "The FrameImage macro is a great way to see what happened in your application at a particular time. Maybe you have a performance problem that only occurs when a certain object is on the screen?" );
} };

AchievementItem* ac_instrumentFramesItems[] = {
    &ai_frameImages,
    nullptr
};

AchievementItem ai_instrumentFrames = { "instrumentFrames", "Instrumenting frames", [](const ctx& c){
        constexpr const char* src = R"(#include "Tracy.hpp"

void Render()
{
    // Render the frame
    SwapBuffers();
    FrameMark;
}
)";

    static SourceContents sc;
    sc.Parse( src );

    ImGui::TextWrapped( "In addition to instrumenting functions, you can also instrument frames. This allows you to see how much time is spent in each frame of your application." );
    ImGui::TextWrapped( "To instrument frames, you need to add the FrameMark macro at the beginning of each frame. This can be done in the main loop of your application, or in a separate function that is called at the beginning of each frame." );
    ImGui::PushFont( c.fixed );
    PrintSource( sc.get() );
    ImGui::PopFont();
    ImGui::TextWrapped( "When you profile your application, you will see a new frame appear on the timeline each time the FrameMark macro is called. This allows you to see how much time is spent in each frame and how many frames are rendered per second." );
    ImGui::TextWrapped( "The FrameMark macro is a great way to see at a glance how your application is performing over time. Maybe there are some performance problems that only appear after a few minutes of running the application? A frame graph is drawn at the top of the profiler window where you can see the timing of all frames." );
    ImGui::TextWrapped( "Note that some applications do not have a frame-based structure, and in such cases, frame instrumentation may not be useful. That's ok." );
}, ac_instrumentFramesItems };

AchievementItem* ac_instrumentationItems[] = { &ai_instrumentationIntro, &ai_instrumentFrames, nullptr };
AchievementCategory ac_instrumentation = { "instrumentation", "Instrumentation", ac_instrumentationItems };


AchievementItem ai_loadTrace = { "loadTrace", "Load a trace", [](const ctx&){
    ImGui::TextWrapped( "You can open a previously saved trace file (or one received from a friend) with the \"" ICON_FA_FOLDER_OPEN " Open saved trace\" button on the welcome screen." );
} };

AchievementItem ai_saveTrace = { "saveTrace", "Save a trace", [](const ctx&){
    ImGui::TextWrapped( "Now that you have traced your application (or are in the process of doing so), you can save it to disk for future reference. You can do this by clicking on the " ICON_FA_WIFI " icon in the top left corner of the screen and then clicking on the \"" ICON_FA_FLOPPY_DISK " Save trace\" button." );
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

AchievementItem* ac_connectToServerUnlock[] = {
    &ai_instrumentationIntro,
    &ai_samplingIntro,
    nullptr
};

AchievementItem ai_connectToServer = { "connectToClient", "First profiling session", [](const ctx&){
    ImGui::TextWrapped( "Let's start our adventure by instrumenting your application and connecting it to the profiler. Here's a quick refresher:" );
    ImGui::TextWrapped( " 1. Integrate Tracy Profiler into your application. This can be done using CMake, Meson, or simply by adding the source files to your project." );
    ImGui::TextWrapped( " 2. Make sure that TracyClient.cpp (or the Tracy library) is included in your build." );
    ImGui::TextWrapped( " 3. Define TRACY_ENABLE in your build configuration, for the whole application. Do not do it in a single source file because it won't work." );
    ImGui::TextWrapped( " 4. Start your application, and \"" ICON_FA_WIFI " Connect\" to it with the profiler." );
    ImGui::TextWrapped( "Please refer to the user manual for more details." );
    if( ImGui::SmallButton( "Download the user manual" ) )
    {
        tracy::OpenWebpage( "https://github.com/wolfpld/tracy/releases" );
    }
}, ac_connectToServerItems, ac_connectToServerUnlock };

AchievementItem ai_globalSettings = { "globalSettings", "Global settings", [](const ctx&){
    ImGui::TextWrapped( "Tracy has a variety of settings that can be adjusted to suit your needs. These settings can be found by clicking on the " ICON_FA_WRENCH " icon on the welcome screen. This will open the about window, where you can expand the \"" ICON_FA_TOOLBOX " Global settings\" menu." );
    ImGui::TextWrapped( "The settings are saved between sessions, so you only need to set them once." );
} };

AchievementItem* ac_achievementsIntroItems[] = {
    &ai_connectToServer,
    &ai_globalSettings,
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
    &ac_sampling,
    nullptr
};

}
