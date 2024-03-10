cmake_minimum_required(VERSION 3.19)
project(capture C CXX ASM)

set(CMAKE_CXX_STANDARD 17)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/server.cmake)

set(CAPTURE_SOURCE
    src/capture.cpp
)

add_executable(capture ${CAPTURE_SOURCE})
target_include_directories(capture PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(capture PRIVATE TracyServer)