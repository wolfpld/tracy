cmake_minimum_required(VERSION 3.16)

set(TRACY_PUBLIC_DIR ${CMAKE_CURRENT_LIST_DIR}/../public)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/version.cmake)

set(CMAKE_CXX_STANDARD 17)

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
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/GitRef.cmake)

set(PROGRAM_FILES
    src/monitor.cpp
)

add_executable(${PROJECT_NAME} ${PROGRAM_FILES} ${TRACY_PUBLIC_DIR}/TracyClient.cpp)
target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC
    $<BUILD_INTERFACE:${TRACY_PUBLIC_DIR}>
    $<INSTALL_INTERFACE:include/tracy>)
target_compile_definitions(${PROJECT_NAME} PRIVATE
    TRACY_ENABLE
    TRACY_MANUAL_LIFETIME
    TRACY_NO_FRAME_IMAGE
)
target_link_libraries(${PROJECT_NAME} PRIVATE
    Threads::Threads
    ${CMAKE_DL_LIBS}
)

add_git_ref(${PROJECT_NAME})

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})