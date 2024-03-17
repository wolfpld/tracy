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
    TracyBadVersion.cpp
    TracyColor.cpp
    TracyEventDebug.cpp
    TracyFileselector.cpp
    TracyFilesystem.cpp
    TracyImGui.cpp
    TracyMicroArchitecture.cpp
    TracyMouse.cpp
    TracyProtoHistory.cpp
    TracySourceContents.cpp
    TracySourceTokenizer.cpp
    TracySourceView.cpp
    TracyStorage.cpp
    TracyTexture.cpp
    TracyTimelineController.cpp
    TracyTimelineItem.cpp
    TracyTimelineItemCpuData.cpp
    TracyTimelineItemGpu.cpp
    TracyTimelineItemPlot.cpp
    TracyTimelineItemThread.cpp
    TracyUserData.cpp
    TracyUtility.cpp
    TracyView.cpp
    TracyView_Annotations.cpp
    TracyView_Callstack.cpp
    TracyView_Compare.cpp
    TracyView_ConnectionState.cpp
    TracyView_ContextSwitch.cpp
    TracyView_CpuData.cpp
    TracyView_FindZone.cpp
    TracyView_FrameOverview.cpp
    TracyView_FrameTimeline.cpp
    TracyView_FrameTree.cpp
    TracyView_GpuTimeline.cpp
    TracyView_Locks.cpp
    TracyView_Memory.cpp
    TracyView_Messages.cpp
    TracyView_Navigation.cpp
    TracyView_NotificationArea.cpp
    TracyView_Options.cpp
    TracyView_Playback.cpp
    TracyView_Plots.cpp
    TracyView_Ranges.cpp
    TracyView_Samples.cpp
    TracyView_Statistics.cpp
    TracyView_Timeline.cpp
    TracyView_TraceInfo.cpp
    TracyView_Utility.cpp
    TracyView_ZoneInfo.cpp
    TracyView_ZoneTimeline.cpp
    TracyWeb.cpp
)

list(TRANSFORM SERVER_FILES PREPEND "src/profiler/")

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