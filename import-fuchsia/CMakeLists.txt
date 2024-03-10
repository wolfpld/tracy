cmake_minimum_required(VERSION 3.19)
project(import-fuchsia C CXX ASM)

set(CMAKE_CXX_STANDARD 17)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/server.cmake)

set(SOURCES
    src/import-fuchsia.cpp
)

add_executable(import-fuchsia ${SOURCES})
target_include_directories(import-fuchsia PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(import-fuchsia PRIVATE TracyServer)