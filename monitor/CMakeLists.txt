cmake_minimum_required(VERSION 3.16)

set(TRACY_PUBLIC_DIR ${CMAKE_CURRENT_LIST_DIR}/../public)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/version.cmake)

set(NO_STATISTICS ON)

set(CMAKE_CXX_STANDARD 20)

project(
    tracy-monitor
    LANGUAGES C CXX
    VERSION ${TRACY_VERSION_STRING}
)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "tracy-monitor is Linux-only")
endif()
if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|aarch64|arm64)$")
    message(FATAL_ERROR "tracy-monitor supports x86_64 and aarch64")
endif()

find_package(Threads REQUIRED)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/config.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/server.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/GitRef.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/util.cmake)

set(PROGRAM_FILES
    src/monitor.cpp
)

# Build the Tracy client through the root project, so that its TRACY_* options
# (TRACY_ON_DEMAND, TRACY_ONLY_LOCALHOST, ...) can be set by the user.
# The options below are required by monitor and are forced; they cannot be overridden.
set(TRACY_ENABLE ON CACHE BOOL "Required by tracy-monitor" FORCE)
set(TRACY_MANUAL_LIFETIME ON CACHE BOOL "Required by tracy-monitor" FORCE)
set(TRACY_NO_FRAME_IMAGE ON CACHE BOOL "Required by tracy-monitor" FORCE)
set(TRACY_STATIC ON CACHE BOOL "Required by tracy-monitor" FORCE)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/.. tracy-client EXCLUDE_FROM_ALL)

add_executable(${PROJECT_NAME} ${PROGRAM_FILES})
target_link_libraries(${PROJECT_NAME} PRIVATE
    Tracy::TracyClient
    TracyServer
    TracyUtil
    Threads::Threads
    ${CMAKE_DL_LIBS}
)

add_git_ref(${PROJECT_NAME})

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})