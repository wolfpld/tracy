
set(TRACY_CLIENT_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/../public/TracyClient.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../public/common/TracyStackFrames.cpp
)

add_library(TracyClient STATIC ${TRACY_CLIENT_SOURCES})
target_include_directories(TracyClient PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../public)
target_compile_definitions(TracyClient PUBLIC TRACY_ENABLE)
if (TRACY_NO_STATISTICS)
    target_compile_definitions(TracyClient PUBLIC TRACY_NO_STATISTICS)
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

list(TRANSFORM SERVER_SOURCES PREPEND ${CMAKE_CURRENT_SOURCE_DIR}/../server/)

add_library(TracyServer STATIC ${SERVER_SOURCES})
target_include_directories(TracyServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../server)
target_link_libraries(TracyServer PUBLIC TracyImGui TracyCapstone TracyZstd TracyClient)

target_compile_definitions(TracyServer PUBLIC NOMINMAX) # Windows.h defines min and max macros which conflict with std::min and std::max

if (NOT NO_TBB)
    target_link_libraries(TracyServer PUBLIC TracyTbb)
endif()

if (TRACY_NO_STATISTICS)
    message(STATUS "Disabling server statistics")
    target_compile_definitions(TracyServer PUBLIC TRACY_NO_STATISTICS)
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