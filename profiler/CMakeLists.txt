cmake_minimum_required(VERSION 3.16)

option(NO_FILESELECTOR "Disable the file selector")
option(GTK_FILESELECTOR "Use the GTK file selector on Linux instead of the xdg-portal one")
option(LEGACY "Instead of Wayland, use the legacy X11 backend on Linux")

find_package(PkgConfig REQUIRED)

include(../cmake/version.cmake)

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

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-march=native" COMPILER_SUPPORTS_MARCH_NATIVE)
if(COMPILER_SUPPORTS_MARCH_NATIVE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
endif()

set(COMMON_FILES
    ../public/common/tracy_lz4.cpp
    ../public/common/tracy_lz4hc.cpp
    ../public/common/TracySocket.cpp
    ../public/common/TracyStackFrames.cpp
    ../public/common/TracySystem.cpp
)

set(SERVER_FILES
    ../server/TracyBadVersion.cpp
    ../server/TracyColor.cpp
    ../server/TracyEventDebug.cpp
    ../server/TracyFileselector.cpp
    ../server/TracyFilesystem.cpp
    ../server/TracyImGui.cpp
    ../server/TracyMemory.cpp
    ../server/TracyMicroArchitecture.cpp
    ../server/TracyMmap.cpp
    ../server/TracyMouse.cpp
    ../server/TracyPrint.cpp
    ../server/TracyProtoHistory.cpp
    ../server/TracySourceContents.cpp
    ../server/TracySourceTokenizer.cpp
    ../server/TracySourceView.cpp
    ../server/TracyStorage.cpp
    ../server/TracyTaskDispatch.cpp
    ../server/TracyTexture.cpp
    ../server/TracyTextureCompression.cpp
    ../server/TracyThreadCompress.cpp
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
    ../server/TracyWorker.cpp
)

set(ZSTD_FILES
    ../zstd/common/debug.c
    ../zstd/common/entropy_common.c
    ../zstd/common/error_private.c
    ../zstd/common/fse_decompress.c
    ../zstd/common/pool.c
    ../zstd/common/threading.c
    ../zstd/common/xxhash.c
    ../zstd/common/zstd_common.c
    ../zstd/compress/fse_compress.c
    ../zstd/compress/hist.c
    ../zstd/compress/huf_compress.c
    ../zstd/compress/zstd_compress.c
    ../zstd/compress/zstd_compress_literals.c
    ../zstd/compress/zstd_compress_sequences.c
    ../zstd/compress/zstd_compress_superblock.c
    ../zstd/compress/zstd_double_fast.c
    ../zstd/compress/zstd_fast.c
    ../zstd/compress/zstd_lazy.c
    ../zstd/compress/zstd_ldm.c
    ../zstd/compress/zstd_opt.c
    ../zstd/compress/zstdmt_compress.c
    ../zstd/decompress/huf_decompress.c
    ../zstd/decompress/huf_decompress_amd64.S
    ../zstd/decompress/zstd_ddict.c
    ../zstd/decompress/zstd_decompress.c
    ../zstd/decompress/zstd_decompress_block.c
    ../zstd/dictBuilder/cover.c
    ../zstd/dictBuilder/divsufsort.c
    ../zstd/dictBuilder/fastcover.c
    ../zstd/dictBuilder/zdict.c
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

set(IMGUI_FILES
    ../imgui/misc/freetype/imgui_freetype.cpp
    ../imgui/imgui_demo.cpp
    ../imgui/imgui_draw.cpp
    ../imgui/imgui_tables.cpp
    ../imgui/imgui_widgets.cpp
    ../imgui/imgui.cpp
)

set(INCLUDES "")
set(LIBS "")

set(NFD_FILES)
if(NO_FILESELECTOR)
    add_compile_definitions(TRACY_NO_FILESELECTOR)
else()
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        enable_language(OBJC)
        set(NFD_FILES ../nfd/nfd_cocoa.m)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT GTK_FILESELECTOR)
        pkg_check_modules(DBUS REQUIRED dbus-1)
        set(INCLUDES "${INCLUDES};${DBUS_INCLUDE_DIRS}")
        set(LIBS "${LIBS};${DBUS_LIBRARIES}")
        set(NFD_FILES ../nfd/nfd_portal.cpp)
    else()
        pkg_check_modules(GTK REQUIRED gtk+-3.0)
        set(INCLUDES "${INCLUDES};${GTK_INCLUDE_DIRS}")
        set(LIBS "${LIBS};${GTK_LIBRARIES}")
        set(NFD_FILES ../nfd/nfd_gtk.cpp)
    endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT LEGACY)
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
    pkg_check_modules(GLFW REQUIRED glfw3)
    set(INCLUDES "${INCLUDES};${GLFW_INCLUDE_DIRS}")
    set(LIBS "${LIBS};${GLFW_LIBRARIES}")
    set(PROFILER_FILES ${PROFILER_FILES}
        src/BackendGlfw.cpp
        src/imgui/imgui_impl_glfw.cpp
    )
endif()

pkg_check_modules(DEPS REQUIRED capstone freetype2)
set(INCLUDES "${INCLUDES};${DEPS_INCLUDE_DIRS}")
set(LIBS "${LIBS};${DEPS_LIBRARIES}")

pkg_check_modules(DEPSOPT tbb)
if(DEPSOPT_FOUND)
    set(INCLUDES "${INCLUDES};${DEPSOPT_INCLUDE_DIRS}")
    set(LIBS "${LIBS};${DEPSOPT_LIBRARIES}")
endif()

include_directories(${INCLUDES})
link_libraries(${LIBS})

include_directories(../imgui)
add_compile_definitions(IMGUI_ENABLE_FREETYPE)

add_executable(${PROJECT_NAME} ${PROFILER_FILES} ${IMGUI_FILES} ${COMMON_FILES} ${SERVER_FILES} ${ZSTD_FILES} ${NFD_FILES})
