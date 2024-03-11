set(TRACY_CLIENT_DIR ${CMAKE_CURRENT_LIST_DIR}/../public)

set(TRACY_CLIENT_SOURCES
    ${TRACY_CLIENT_DIR}/common/tracy_lz4.cpp
    ${TRACY_CLIENT_DIR}/common/tracy_lz4hc.cpp
    ${TRACY_CLIENT_DIR}/common/TracySocket.cpp
    ${TRACY_CLIENT_DIR}/common/TracyStackFrames.cpp
    ${TRACY_CLIENT_DIR}/common/TracySystem.cpp
)

add_library(TracyClient STATIC ${TRACY_CLIENT_SOURCES})
target_include_directories(TracyClient PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../public)
if (TRACY_NO_STATISTICS)
    target_compile_definitions(TracyClient PUBLIC TRACY_NO_STATISTICS)
endif()

# Public dependency on some libraries required when using Mingw
if(WIN32)
    target_link_libraries(TracyClient PUBLIC wsock32 ws2_32 dbghelp)
endif()

set(SERVER_SOURCES
    TracyEventDebug.cpp
    TracyTimelineController.cpp
    TracyView_Playback.cpp
    TracyTexture.cpp
    TracyView_Locks.cpp
    TracyView_Memory.cpp
    TracyFileselector.cpp
    TracyView_Compare.cpp
    TracyView_ZoneInfo.cpp
    TracyView_Callstack.cpp
    TracySourceContents.cpp
    TracyPrint.cpp
    TracyStorage.cpp
    TracyTextureCompression.cpp
    TracySourceView.cpp
    TracyView_ContextSwitch.cpp
    TracyUserData.cpp
    TracySourceTokenizer.cpp
    TracyView_Statistics.cpp
    TracyView_Timeline.cpp
    TracyUtility.cpp
    TracyTimelineItemCpuData.cpp
    TracyView_FrameTree.cpp
    TracyMicroArchitecture.cpp
    TracyView_Ranges.cpp
    TracyView.cpp
    TracyMemory.cpp
    TracyView_ConnectionState.cpp
    TracyView_Navigation.cpp
    TracyView_Utility.cpp
    TracyView_Plots.cpp
    TracyProtoHistory.cpp
    TracyView_FrameTimeline.cpp
    TracyView_FindZone.cpp
    TracyThreadCompress.cpp
    TracyImGui.cpp
    TracyView_GpuTimeline.cpp
    TracyTaskDispatch.cpp
    TracyTimelineItemThread.cpp
    TracyTimelineItemPlot.cpp
    TracyWeb.cpp
    TracyTimelineItem.cpp
    TracyColor.cpp
    TracyWorker.cpp
    TracyView_FrameOverview.cpp
    TracyView_Samples.cpp
    TracyMouse.cpp
    TracyView_Messages.cpp
    TracyMmap.cpp
    TracyView_ZoneTimeline.cpp
    TracyView_Annotations.cpp
    TracyFilesystem.cpp
    TracyView_TraceInfo.cpp
    TracyView_NotificationArea.cpp
    TracyTimelineItemGpu.cpp
    TracyView_CpuData.cpp
    TracyBadVersion.cpp
    TracyView_Options.cpp
)

set(TRACY_NO_STATS_SOURCE
    TracyPrint.cpp
    TracyWorker.cpp
    TracyThreadCompress.cpp
    TracyMemory.cpp
    TracyTextureCompression.cpp
    TracyTaskDispatch.cpp
    TracyMmap.cpp
)

if (TRACY_NO_STATISTICS)
    message(STATUS "Building TracyServer without statistics")
    list(TRANSFORM TRACY_NO_STATS_SOURCE PREPEND ${CMAKE_CURRENT_SOURCE_DIR}/../server/)
    set(SOURCES ${TRACY_NO_STATS_SOURCE})
else()
    list(TRANSFORM SERVER_SOURCES PREPEND ${CMAKE_CURRENT_SOURCE_DIR}/../server/)
    set(SOURCES ${SERVER_SOURCES})
endif()

add_library(TracyServer STATIC ${SOURCES})
target_include_directories(TracyServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../server)
target_link_libraries(TracyServer PUBLIC TracyImGui TracyCapstone TracyZstd TracyClient)

target_compile_definitions(TracyServer PUBLIC NOMINMAX) # Windows.h defines min and max macros which conflict with std::min and std::max

if (NOT NO_TBB)
    target_link_libraries(TracyServer PUBLIC TracyTbb)
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if (CMAKE_LINKER MATCHES "ld.mold")
        set(LDFLAGS "-fuse-ld=mold")
    endif()
endif()

if (NOT TRACY_NO_ISA_EXTENSIONS)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=native")
    elseif(UNIX)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
    endif()
endif()