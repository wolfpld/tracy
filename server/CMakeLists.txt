add_library(
  server STATIC
  TracyBadVersion.cpp
  TracyColor.cpp
  TracyEventDebug.cpp
  TracyFileselector.cpp
  TracyFilesystem.cpp
  TracyImGui.cpp
  TracyMemory.cpp
  TracyMicroArchitecture.cpp
  TracyMmap.cpp
  TracyMouse.cpp
  TracyPrint.cpp
  TracyProtoHistory.cpp
  TracySourceContents.cpp
  TracySourceTokenizer.cpp
  TracySourceView.cpp
  TracyStorage.cpp
  TracyTaskDispatch.cpp
  TracyTexture.cpp
  TracyTextureCompression.cpp
  TracyThreadCompress.cpp
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
  TracyWorker.cpp)

set_default_compile_options(server)

find_package(Capstone REQUIRED)

target_include_directories(server PUBLIC "${CMAKE_SOURCE_DIR}/imgui")
target_link_libraries(server PUBLIC capstone::capstone zstd public.common)

if(UNIX AND NOT APPLE)
  # On Linux std algorithms use tbb
  find_package(TBB REQUIRED COMPONENTS tbb)

  target_link_libraries(server PUBLIC TBB::tbb Threads::Threads)
endif()
