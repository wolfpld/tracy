cmake_minimum_required(VERSION 3.19)
project(update C CXX ASM)

set(CMAKE_CXX_STANDARD 17)

set(TRACY_NO_STATISTICS ON)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/server.cmake)

set(UPDATE_SOURCE
    src/OfflineSymbolResolverDbgHelper.cpp
    src/OfflineSymbolResolver.cpp
    src/OfflineSymbolResolverAddr2Line.cpp
    src/update.cpp
)

add_executable(update ${UPDATE_SOURCE})
target_include_directories(update PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(update PRIVATE TracyServer TracyGetOpt)