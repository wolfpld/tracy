cmake_minimum_required(VERSION 3.16)

set(NO_STATISTICS ON)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/version.cmake)

set(CMAKE_CXX_STANDARD 20)

project(
    tracy-import-strace
    LANGUAGES C CXX
    VERSION ${TRACY_VERSION_STRING}
)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/config.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/server.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/GitRef.cmake)

add_executable(tracy-import-strace
    src/stracy.cpp
)
add_git_ref(tracy-import-strace)
target_link_libraries(tracy-import-strace PRIVATE TracyServer)

set_property(DIRECTORY ${CMAKE_CURRENT_LIST_DIR} PROPERTY VS_STARTUP_PROJECT tracy-import-strace)
