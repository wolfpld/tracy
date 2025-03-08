cmake_minimum_required(VERSION 3.21)

option(NO_FILESELECTOR "Disable the file selector" OFF)
option(GTK_FILESELECTOR "Use the GTK file selector on Linux instead of the xdg-portal one" OFF)
option(LEGACY "Instead of Wayland, use the legacy X11 backend on Linux" OFF)
option(NO_ISA_EXTENSIONS "Disable ISA extensions (don't pass -march=native or -mcpu=native to the compiler)" OFF)
option(NO_STATISTICS "Disable calculation of statistics" OFF)
option(SELF_PROFILE "Enable self-profiling" OFF)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/version.cmake)

set(CMAKE_CXX_STANDARD 20)

project(
    tracy-profiler
    LANGUAGES C CXX
    VERSION ${TRACY_VERSION_STRING}
)

if(SELF_PROFILE)
    add_definitions(-DTRACY_ENABLE)
    add_compile_options(-g -O3 -fno-omit-frame-pointer)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/config.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/server.cmake)

set(SERVER_FILES
    TracyAchievementData.cpp
    TracyAchievements.cpp
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
    TracyView_FlameGraph.cpp
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

set(INCLUDES "${CMAKE_CURRENT_BINARY_DIR}")
set(LIBS "")

if(USE_WAYLAND)
    pkg_check_modules(WAYLAND REQUIRED egl wayland-egl wayland-cursor xkbcommon)
    set(LIBS "${LIBS};${WAYLAND_LIBRARIES}")
    set(PROFILER_FILES ${PROFILER_FILES}
        src/BackendWayland.cpp
    )

    include(${CMAKE_CURRENT_LIST_DIR}/../cmake/FindWaylandScanner.cmake)

    CPMAddPackage(
        NAME wayland-protocols
        GIT_REPOSITORY https://gitlab.freedesktop.org/wayland/wayland-protocols.git
        GIT_TAG 1.37
        DOWNLOAD_ONLY YES
    )

    ecm_add_wayland_client_protocol(PROFILER_FILES
        PROTOCOL ${wayland-protocols_SOURCE_DIR}/stable/xdg-shell/xdg-shell.xml
        BASENAME xdg-shell
    )
    ecm_add_wayland_client_protocol(PROFILER_FILES
        PROTOCOL ${wayland-protocols_SOURCE_DIR}/staging/xdg-activation/xdg-activation-v1.xml
        BASENAME xdg-activation
    )
    ecm_add_wayland_client_protocol(PROFILER_FILES
        PROTOCOL ${wayland-protocols_SOURCE_DIR}/unstable/xdg-decoration/xdg-decoration-unstable-v1.xml
        BASENAME xdg-decoration
    )
    ecm_add_wayland_client_protocol(PROFILER_FILES
        PROTOCOL ${wayland-protocols_SOURCE_DIR}/staging/fractional-scale/fractional-scale-v1.xml
        BASENAME fractional-scale
    )
    ecm_add_wayland_client_protocol(PROFILER_FILES
        PROTOCOL ${wayland-protocols_SOURCE_DIR}/stable/viewporter/viewporter.xml
        BASENAME viewporter
    )
    ecm_add_wayland_client_protocol(PROFILER_FILES
        PROTOCOL ${wayland-protocols_SOURCE_DIR}/staging/cursor-shape/cursor-shape-v1.xml
        BASENAME cursor-shape
    )
    ecm_add_wayland_client_protocol(PROFILER_FILES
        PROTOCOL ${wayland-protocols_SOURCE_DIR}/unstable/tablet/tablet-unstable-v2.xml
        BASENAME tablet
    )
    ecm_add_wayland_client_protocol(PROFILER_FILES
        PROTOCOL ${wayland-protocols_SOURCE_DIR}/staging/xdg-toplevel-icon/xdg-toplevel-icon-v1.xml
        BASENAME xdg-toplevel-icon
    )
elseif(EMSCRIPTEN)
    set(PROFILER_FILES ${PROFILER_FILES}
        src/BackendEmscripten.cpp
    )
else()
    set(PROFILER_FILES ${PROFILER_FILES}
        src/BackendGlfw.cpp
        ${ImGui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    )
endif()

include_directories(${INCLUDES})
link_libraries(${LIBS})

if(SELF_PROFILE)
    set(PROFILER_FILES ${PROFILER_FILES}
        ../public/TracyClient.cpp
    )
endif()

if(WIN32)
    set(PROFILER_FILES ${PROFILER_FILES}
        win32/Tracy.manifest
        win32/Tracy.rc
    )
    add_executable(${PROJECT_NAME} WIN32 ${PROFILER_FILES} ${COMMON_FILES} ${SERVER_FILES})
    set_property(DIRECTORY ${CMAKE_CURRENT_LIST_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})
else()
    add_executable(${PROJECT_NAME} ${PROFILER_FILES} ${COMMON_FILES} ${SERVER_FILES})
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE TracyServer TracyImGui)

if(NOT DEFINED GIT_REV)
    set(GIT_REV "HEAD")
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_custom_target(git-ref
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/../extra/git-ref.py ${GIT_REV}
    BYPRODUCTS GitRef.hpp
)
add_dependencies(${PROJECT_NAME} git-ref)

if(NOT EMSCRIPTEN)
    target_link_libraries(${PROJECT_NAME} PRIVATE TracyNfd)
    if (NOT USE_WAYLAND)
        target_link_libraries(${PROJECT_NAME} PRIVATE TracyGlfw3)
    endif()
endif()

if(EMSCRIPTEN)
    target_link_options(${PROJECT_NAME} PRIVATE -pthread -sASSERTIONS=0 -sINITIAL_MEMORY=384mb -sALLOW_MEMORY_GROWTH=1 -sMAXIMUM_MEMORY=4gb -sSTACK_SIZE=1048576 -sWASM_BIGINT=1 -sPTHREAD_POOL_SIZE=8 -sEXPORTED_FUNCTIONS=_main,_nativeOpenFile -sEXPORTED_RUNTIME_METHODS=ccall -sENVIRONMENT=web,worker --preload-file embed.tracy)

    file(DOWNLOAD https://share.nereid.pl/i/embed.tracy ${CMAKE_CURRENT_BINARY_DIR}/embed.tracy EXPECTED_MD5 ca0fa4f01e7b8ca5581daa16b16c768d)
    file(COPY ${CMAKE_CURRENT_LIST_DIR}/wasm/index.html DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    file(COPY ${CMAKE_CURRENT_LIST_DIR}/wasm/httpd.py DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    file(COPY_FILE ${CMAKE_CURRENT_LIST_DIR}/../icon/icon.svg ${CMAKE_CURRENT_BINARY_DIR}/favicon.svg)
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
