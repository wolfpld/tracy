cmake_minimum_required(VERSION 3.16)

option(NO_FILESELECTOR "Disable the file selector" OFF)
option(GTK_FILESELECTOR "Use the GTK file selector on Linux instead of the xdg-portal one" OFF)
option(LEGACY "Instead of Wayland, use the legacy X11 backend on Linux" OFF)
option(NO_ISA_EXTENSIONS "Disable ISA extensions (don't pass -march=native or -mcpu=native to the compiler)" OFF)
option(NO_STATISTICS "Disable calculation of statistics" OFF)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/version.cmake)

set(TRACY_VERSION_MAJOR ${major})
set(TRACY_VERSION_MINOR ${minor})
set(TRACY_VERSION_PATCH ${patch})
set(TRACY_VERSION_STRING "${TRACY_VERSION_MAJOR}.${TRACY_VERSION_MINOR}.${TRACY_VERSION_PATCH}")

set(CMAKE_CXX_STANDARD 20)

project(
    tracy-profiler
    LANGUAGES ASM C CXX
    VERSION ${TRACY_VERSION_STRING}
)

if (NOT NO_ISA_EXTENSIONS)
    include(CheckCXXCompilerFlag)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        CHECK_CXX_COMPILER_FLAG("-mcpu=native" COMPILER_SUPPORTS_MCPU_NATIVE)
        if(COMPILER_SUPPORTS_MARCH_NATIVE)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=native")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=native")
        endif()
    else()
        CHECK_CXX_COMPILER_FLAG("-march=native" COMPILER_SUPPORTS_MARCH_NATIVE)
        if(COMPILER_SUPPORTS_MARCH_NATIVE)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
        endif()
    endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT LEGACY)
    set(USE_WAYLAND ON)
else()
    set(USE_WAYLAND OFF)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/server.cmake)

set(SERVER_FILES
    ../server/TracyBadVersion.cpp
    ../server/TracyColor.cpp
    ../server/TracyEventDebug.cpp
    ../server/TracyFileselector.cpp
    ../server/TracyFilesystem.cpp
    ../server/TracyImGui.cpp
    ../server/TracyMicroArchitecture.cpp
    ../server/TracyMouse.cpp
    ../server/TracyProtoHistory.cpp
    ../server/TracySourceContents.cpp
    ../server/TracySourceTokenizer.cpp
    ../server/TracySourceView.cpp
    ../server/TracyStorage.cpp
    ../server/TracyTexture.cpp
    ../server/TracyTimelineController.cpp
    ../server/TracyTimelineItem.cpp
    ../server/TracyTimelineItemCpuData.cpp
    ../server/TracyTimelineItemGpu.cpp
    ../server/TracyTimelineItemPlot.cpp
    ../server/TracyTimelineItemThread.cpp
    ../server/TracyUserData.cpp
    ../server/TracyUtility.cpp
    ../server/TracyView.cpp
    ../server/TracyView_Annotations.cpp
    ../server/TracyView_Callstack.cpp
    ../server/TracyView_Compare.cpp
    ../server/TracyView_ConnectionState.cpp
    ../server/TracyView_ContextSwitch.cpp
    ../server/TracyView_CpuData.cpp
    ../server/TracyView_FindZone.cpp
    ../server/TracyView_FrameOverview.cpp
    ../server/TracyView_FrameTimeline.cpp
    ../server/TracyView_FrameTree.cpp
    ../server/TracyView_GpuTimeline.cpp
    ../server/TracyView_Locks.cpp
    ../server/TracyView_Memory.cpp
    ../server/TracyView_Messages.cpp
    ../server/TracyView_Navigation.cpp
    ../server/TracyView_NotificationArea.cpp
    ../server/TracyView_Options.cpp
    ../server/TracyView_Playback.cpp
    ../server/TracyView_Plots.cpp
    ../server/TracyView_Ranges.cpp
    ../server/TracyView_Samples.cpp
    ../server/TracyView_Statistics.cpp
    ../server/TracyView_Timeline.cpp
    ../server/TracyView_TraceInfo.cpp
    ../server/TracyView_Utility.cpp
    ../server/TracyView_ZoneInfo.cpp
    ../server/TracyView_ZoneTimeline.cpp
    ../server/TracyWeb.cpp
)

set(PROFILER_FILES
    src/imgui/imgui_impl_opengl3.cpp
    src/ConnectionHistory.cpp
    src/Filters.cpp
    src/Fonts.cpp
    src/HttpRequest.cpp
    src/ImGuiContext.cpp
    src/ini.c
    src/IsElevated.cpp
    src/main.cpp
    src/ResolvService.cpp
    src/RunQueue.cpp
    src/WindowPosition.cpp
    src/winmain.cpp
    src/winmainArchDiscovery.cpp
)

set(INCLUDES "")
set(LIBS "")

if(USE_WAYLAND)
    pkg_check_modules(WAYLAND REQUIRED egl wayland-egl wayland-cursor xkbcommon)
    set(INCLUDES "${INCLUDES};${WAYLAND_INCLUDE_DIRS}")
    set(LIBS "${LIBS};${WAYLAND_LIBRARIES}")
    set(PROFILER_FILES ${PROFILER_FILES}
        src/BackendWayland.cpp
        src/wayland/xdg-activation.c
        src/wayland/xdg-decoration.c
        src/wayland/xdg-shell.c
    )
else()
    set(PROFILER_FILES ${PROFILER_FILES}
        src/BackendGlfw.cpp
        src/imgui/imgui_impl_glfw.cpp
    )
endif()

include_directories(${INCLUDES})
link_libraries(${LIBS})

if(WIN32)
    set(PROFILER_FILES ${PROFILER_FILES}
        win32/Tracy.manifest
        win32/Tracy.rc
    )
    add_executable(${PROJECT_NAME} WIN32 ${PROFILER_FILES} ${COMMON_FILES} ${SERVER_FILES})
else()
    add_executable(${PROJECT_NAME} ${PROFILER_FILES} ${COMMON_FILES} ${SERVER_FILES})
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE TracyServer TracyImGui TracyNfd)

if(UNIX)
    target_link_libraries(${PROJECT_NAME} PRIVATE TracyTbb)
endif()

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)
endif()