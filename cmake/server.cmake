set(TRACY_COMMON_DIR ${CMAKE_CURRENT_LIST_DIR}/../public/common)

set(TRACY_COMMON_SOURCES
    tracy_lz4.cpp
    tracy_lz4hc.cpp
    TracySocket.cpp
    TracyStackFrames.cpp
    TracySystem.cpp
)

list(TRANSFORM TRACY_COMMON_SOURCES PREPEND "${TRACY_COMMON_DIR}/")


set(TRACY_SERVER_DIR ${CMAKE_CURRENT_LIST_DIR}/../server)

set(TRACY_SERVER_SOURCES
    TracyMemory.cpp
    TracyMmap.cpp
    TracyPrint.cpp
    TracySysUtil.cpp
    TracyTaskDispatch.cpp
    TracyTextureCompression.cpp
    TracyThreadCompress.cpp
    TracyWorker.cpp
)

list(TRANSFORM TRACY_SERVER_SOURCES PREPEND "${TRACY_SERVER_DIR}/")


add_library(TracyServer STATIC ${TRACY_COMMON_SOURCES} ${TRACY_SERVER_SOURCES})
target_include_directories(TracyServer PUBLIC ${TRACY_COMMON_DIR} ${TRACY_SERVER_DIR})
target_link_libraries(TracyServer PUBLIC TracyCapstone TracyZstd)
if(NO_STATISTICS)
    target_compile_definitions(TracyServer PUBLIC TRACY_NO_STATISTICS)
endif()

if(NOT NO_PARALLEL_STL AND UNIX AND NOT APPLE AND NOT EMSCRIPTEN)
    target_link_libraries(TracyServer PRIVATE TracyTbb)
endif()
