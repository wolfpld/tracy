cmake_minimum_required(VERSION 3.0.0)
project(TracyWin32 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "ON" FORCE)


# add Freetype
include(FindFreetype)
include_directories(${FREETYPE_INCLUDE_DIRS})

# enable FetchContent
include(FetchContent)

# add glfw
FetchContent_Declare(
    glfw_dev
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG        3.3.8
    )
# unnecessary       
set(GLFW_BUILD_EXAMPLES FALSE) 
set(GLFW_BUILD_DOCS FALSE) 
set(GLFW_BUILD_TESTS FALSE) 
FetchContent_MakeAvailable(glfw_dev)


# for capstone set CMAKE_C_COMPILE_OBJECT ?    
set(CMAKE_C_COMPILE_OBJECT "<CMAKE_C_COMPILER> <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>")

# add capstone
FetchContent_Declare(
    capstone_dev
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG        6eb1db9c04113ac0a05f2dfd228704c84775530f
    )
FetchContent_MakeAvailable(capstone_dev)


# based on Tracy.vcxproj    
set(SRC_ALL  
    "../../../imgui/imgui.cpp" 
    "../../../imgui/imgui.cpp" 
    "../../../imgui/imgui_demo.cpp" 
    "../../../imgui/imgui_draw.cpp" 
    "../../../imgui/imgui_tables.cpp" 
    "../../../imgui/imgui_widgets.cpp" 
    "../../../imgui/misc/freetype/imgui_freetype.cpp" 
    "../../../nfd/nfd_win.cpp" 
    "../../../public/common/TracySocket.cpp" 
    "../../../public/common/TracyStackFrames.cpp" 
    "../../../public/common/TracySystem.cpp" 
    "../../../public/common/tracy_lz4.cpp" 
    "../../../public/common/tracy_lz4hc.cpp" 
    "../../../server/TracyBadVersion.cpp" 
    "../../../server/TracyColor.cpp" 
    "../../../server/TracyFileselector.cpp" 
    "../../../server/TracyFilesystem.cpp" 
    "../../../server/TracyImGui.cpp" 
    "../../../server/TracyMemory.cpp" 
    "../../../server/TracyMicroArchitecture.cpp" 
    "../../../server/TracyMmap.cpp" 
    "../../../server/TracyMouse.cpp" 
    "../../../server/TracyPrint.cpp" 
    "../../../server/TracyProtoHistory.cpp" 
    "../../../server/TracySourceContents.cpp" 
    "../../../server/TracySourceTokenizer.cpp" 
    "../../../server/TracySourceView.cpp" 
    "../../../server/TracyStorage.cpp" 
    "../../../server/TracyTaskDispatch.cpp" 
    "../../../server/TracyTexture.cpp" 
    "../../../server/TracyTextureCompression.cpp" 
    "../../../server/TracyThreadCompress.cpp" 
    "../../../server/TracyTimelineController.cpp" 
    "../../../server/TracyTimelineItem.cpp" 
    "../../../server/TracyTimelineItemCpuData.cpp" 
    "../../../server/TracyTimelineItemGpu.cpp" 
    "../../../server/TracyTimelineItemPlot.cpp" 
    "../../../server/TracyTimelineItemThread.cpp" 
    "../../../server/TracyUserData.cpp" 
    "../../../server/TracyUtility.cpp" 
    "../../../server/TracyView.cpp" 
    "../../../server/TracyView_Annotations.cpp" 
    "../../../server/TracyView_Callstack.cpp" 
    "../../../server/TracyView_Compare.cpp" 
    "../../../server/TracyView_ConnectionState.cpp" 
    "../../../server/TracyView_ContextSwitch.cpp" 
    "../../../server/TracyView_CpuData.cpp" 
    "../../../server/TracyView_FindZone.cpp" 
    "../../../server/TracyView_FrameOverview.cpp" 
    "../../../server/TracyView_FrameTimeline.cpp" 
    "../../../server/TracyView_FrameTree.cpp" 
    "../../../server/TracyView_GpuTimeline.cpp" 
    "../../../server/TracyView_Locks.cpp" 
    "../../../server/TracyView_Memory.cpp" 
    "../../../server/TracyView_Messages.cpp" 
    "../../../server/TracyView_Navigation.cpp" 
    "../../../server/TracyView_NotificationArea.cpp" 
    "../../../server/TracyView_Options.cpp" 
    "../../../server/TracyView_Playback.cpp" 
    "../../../server/TracyView_Plots.cpp" 
    "../../../server/TracyView_Ranges.cpp" 
    "../../../server/TracyView_Samples.cpp" 
    "../../../server/TracyView_Statistics.cpp" 
    "../../../server/TracyView_Timeline.cpp" 
    "../../../server/TracyView_TraceInfo.cpp" 
    "../../../server/TracyView_Utility.cpp" 
    "../../../server/TracyView_ZoneInfo.cpp" 
    "../../../server/TracyView_ZoneTimeline.cpp" 
    "../../../server/TracyWeb.cpp" 
    "../../../server/TracyWorker.cpp" 
    "../../../zstd/common/debug.c" 
    "../../../zstd/common/entropy_common.c" 
    "../../../zstd/common/error_private.c" 
    "../../../zstd/common/fse_decompress.c" 
    "../../../zstd/common/pool.c" 
    "../../../zstd/common/threading.c" 
    "../../../zstd/common/xxhash.c" 
    "../../../zstd/common/zstd_common.c" 
    "../../../zstd/compress/fse_compress.c" 
    "../../../zstd/compress/hist.c" 
    "../../../zstd/compress/huf_compress.c" 
    "../../../zstd/compress/zstdmt_compress.c" 
    "../../../zstd/compress/zstd_compress.c" 
    "../../../zstd/compress/zstd_compress_literals.c" 
    "../../../zstd/compress/zstd_compress_sequences.c" 
    "../../../zstd/compress/zstd_compress_superblock.c" 
    "../../../zstd/compress/zstd_double_fast.c" 
    "../../../zstd/compress/zstd_fast.c" 
    "../../../zstd/compress/zstd_lazy.c" 
    "../../../zstd/compress/zstd_ldm.c" 
    "../../../zstd/compress/zstd_opt.c" 
    "../../../zstd/decompress/huf_decompress.c" 
    "../../../zstd/decompress/zstd_ddict.c" 
    "../../../zstd/decompress/zstd_decompress.c" 
    "../../../zstd/decompress/zstd_decompress_block.c" 

    "../../../zstd/dictBuilder/cover.c" 
    "../../../zstd/dictBuilder/divsufsort.c" 
    "../../../zstd/dictBuilder/fastcover.c" 
    "../../../zstd/dictBuilder/zdict.c" 
    "../../src/BackendGlfw.cpp" 
    "../../src/ConnectionHistory.cpp" 
    "../../src/Filters.cpp" 
    "../../src/Fonts.cpp" 
    "../../src/HttpRequest.cpp" 
    "../../src/ImGuiContext.cpp" 
    "../../src/imgui/imgui_impl_glfw.cpp" 
    "../../src/imgui/imgui_impl_opengl3.cpp" 
    "../../src/IsElevated.cpp" 
    "../../src/main.cpp" 
    "../../src/ResolvService.cpp" 
    "../../src/RunQueue.cpp" 
    "../../src/WindowPosition.cpp" 
    "../../src/winmain.cpp"


    "../../src/winmainArchDiscovery.cpp" 

    "../../../imgui/imconfig.h" 
    "../../../imgui/imgui.h" 
    "../../../imgui/imgui_internal.h" 
    "../../../imgui/imstb_rectpack.h" 
    "../../../imgui/imstb_textedit.h" 
    "../../../imgui/imstb_truetype.h" 
    "../../../imgui/misc/freetype/imgui_freetype.h" 
    "../../../nfd/nfd.h" 
    "../../../public/common/TracyAlign.hpp" 
    "../../../public/common/TracyAlloc.hpp" 
    "../../../public/common/TracyApi.h" 
    "../../../public/common/TracyColor.hpp" 
    "../../../public/common/TracyForceInline.hpp" 
    "../../../public/common/TracyMutex.hpp" 
    "../../../public/common/TracyProtocol.hpp" 
    "../../../public/common/TracyQueue.hpp" 
    "../../../public/common/TracySocket.hpp" 
    "../../../public/common/TracyStackFrames.hpp" 
    "../../../public/common/TracySystem.hpp" 
    "../../../public/common/TracyUwp.hpp" 
    "../../../public/common/TracyVersion.hpp" 
    "../../../public/common/TracyYield.hpp" 
    "../../../public/common/tracy_lz4.hpp" 
    "../../../public/common/tracy_lz4hc.hpp" 
    "../../../server/IconsFontAwesome6.h" 
    "../../../server/TracyBadVersion.hpp" 
    "../../../server/TracyBuzzAnim.hpp" 
    "../../../server/TracyCharUtil.hpp" 
    "../../../server/TracyColor.hpp" 
    "../../../server/TracyDecayValue.hpp" 
    "../../../server/TracyEvent.hpp" 
    "../../../server/TracyFileHeader.hpp" 
    "../../../server/TracyFileRead.hpp" 
    "../../../server/TracyFileselector.hpp" 
    "../../../server/TracyFilesystem.hpp" 
    "../../../server/TracyFileWrite.hpp" 
    "../../../server/TracyImGui.hpp" 
    "../../../server/TracyMemory.hpp" 
    "../../../server/TracyMicroArchitecture.hpp" 
    "../../../server/TracyMmap.hpp" 
    "../../../server/TracyMouse.hpp" 
    "../../../server/TracyPopcnt.hpp" 
    "../../../server/TracyPrint.hpp" 
    "../../../server/TracyProtoHistory.hpp" 
    "../../../server/TracyShortPtr.hpp" 
    "../../../server/TracySlab.hpp" 
    "../../../server/TracySort.hpp" 
    "../../../server/TracySortedVector.hpp" 
    "../../../server/TracySourceContents.hpp" 
    "../../../server/TracySourceTokenizer.hpp" 
    "../../../server/TracySourceView.hpp" 
    "../../../server/TracyStorage.hpp" 
    "../../../server/TracyStringDiscovery.hpp" 
    "../../../server/TracyTaskDispatch.hpp" 
    "../../../server/TracyTexture.hpp" 
    "../../../server/TracyTextureCompression.hpp" 
    "../../../server/TracyThreadCompress.hpp" 
    "../../../server/TracyTimelineController.hpp" 
    "../../../server/TracyTimelineItem.hpp" 
    "../../../server/TracyTimelineItemCpuData.hpp" 
    "../../../server/TracyTimelineItemGpu.hpp" 
    "../../../server/TracyTimelineItemPlot.hpp" 
    "../../../server/TracyTimelineItemThread.hpp" 
    "../../../server/TracyUserData.hpp" 
    "../../../server/TracyUtility.hpp" 
    "../../../server/TracyVarArray.hpp" 
    "../../../server/TracyVector.hpp" 
    "../../../server/TracyView.hpp" 
    "../../../server/TracyViewData.hpp" 
    "../../../server/TracyWeb.hpp" 
    "../../../server/TracyWorker.hpp" 
    "../../../server/tracy_pdqsort.h" 
    "../../../server/tracy_robin_hood.h" 
    "../../../server/tracy_xxhash.h" 
    "../../../zstd/common/bitstream.h" 
    "../../../zstd/common/compiler.h" 
    "../../../zstd/common/cpu.h" 
    "../../../zstd/common/debug.h" 
    "../../../zstd/common/error_private.h" 
    "../../../zstd/common/fse.h" 
    "../../../zstd/common/huf.h" 
    "../../../zstd/common/mem.h" 
    "../../../zstd/common/pool.h" 
    "../../../zstd/common/portability_macros.h" 
    "../../../zstd/common/threading.h" 
    "../../../zstd/common/xxhash.h" 
    "../../../zstd/common/zstd_deps.h" 
    "../../../zstd/common/zstd_internal.h" 
    "../../../zstd/common/zstd_trace.h" 
    "../../../zstd/compress/clevels.h" 
    "../../../zstd/compress/hist.h" 
    "../../../zstd/compress/zstdmt_compress.h" 
    "../../../zstd/compress/zstd_compress_internal.h" 
    "../../../zstd/compress/zstd_compress_literals.h" 
    "../../../zstd/compress/zstd_compress_sequences.h" 
    "../../../zstd/compress/zstd_compress_superblock.h" 
    "../../../zstd/compress/zstd_cwksp.h" 
    "../../../zstd/compress/zstd_double_fast.h" 
    "../../../zstd/compress/zstd_fast.h" 
    "../../../zstd/compress/zstd_lazy.h" 
    "../../../zstd/compress/zstd_ldm.h" 
    "../../../zstd/compress/zstd_ldm_geartab.h" 
    "../../../zstd/compress/zstd_opt.h" 
    "../../../zstd/decompress/zstd_ddict.h" 
    "../../../zstd/decompress/zstd_decompress_block.h" 
    "../../../zstd/decompress/zstd_decompress_internal.h" 
    "../../../zstd/dictBuilder/cover.h" 
    "../../../zstd/dictBuilder/divsufsort.h" 
    "../../../zstd/zdict.h" 
    "../../../zstd/zstd.h" 
    "../../../zstd/zstd_errors.h" 
    "../../src/Backend.hpp" 
    "../../src/ConnectionHistory.hpp" 
    "../../src/Filters.hpp" 
    "../../src/Fonts.hpp" 
    "../../src/font/DroidSans.hpp" 
    "../../src/font/FiraCodeRetina.hpp" 
    "../../src/font/FontAwesomeSolid.hpp" 
    "../../src/HttpRequest.hpp" 
    "../../src/icon.hpp" 
    "../../src/ImGuiContext.hpp" 
    "../../src/imgui/imgui_impl_glfw.h" 
    "../../src/imgui/imgui_impl_opengl3.h" 
    "../../src/imgui/imgui_impl_opengl3_loader.h" 
    "../../src/IsElevated.hpp" 
    "../../src/ResolvService.hpp" 
    "../../src/RunQueue.hpp" 
    "../../src/stb_image.h" 
    "../../src/WindowPosition.hpp" 

    "Tracy.rc"
)

add_executable(Tracy ${SRC_ALL})

target_include_directories(Tracy PRIVATE "../../../imgui/" )
target_include_directories(Tracy PRIVATE ${FREETYPE_INCLUDE_DIRS})
target_include_directories(Tracy PRIVATE "${capstone_dev_SOURCE_DIR}/include/capstone")



if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # using Clang
  target_compile_definitions(Tracy PRIVATE TODO_CMAKE_WIN_BUILD  NO_PARALLEL_SORT)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  # using GCC
  target_compile_definitions(Tracy PRIVATE TODO_CMAKE_WIN_BUILD)
endif()  


target_link_libraries(
    Tracy 
        PRIVATE 
            capstone::capstone 
            glfw 
            ws2_32.lib 
            Dbghelp.lib 
            advapi32.lib 
            tbb12      # https://packages.msys2.org/base/mingw-w64-tbb
            freetype)