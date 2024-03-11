cmake_minimum_required(VERSION 3.19)
project(import-chrome C CXX ASM)

set(CMAKE_CXX_STANDARD 17)

set(TRACY_NO_STATISTICS ON)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/server.cmake)

set(SOURCES
    src/import-chrome.cpp
)

add_executable(import-chrome ${SOURCES})
target_include_directories(import-chrome PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(import-chrome PRIVATE TracyServer TracyGetOpt)