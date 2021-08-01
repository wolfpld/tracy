cmake_minimum_required(VERSION 3.10)

project(Tracy LANGUAGES CXX)

find_package(Threads REQUIRED)

option(TRACY_ENABLE "Enable profiling" ON)
option(TRACY_ON_DEMAND "On-demand profiling" OFF)
option(TRACY_CALLSTACK "Collect call stacks" OFF)
option(TRACY_ONLY_LOCALHOST "Only listen on the localhost interface" OFF)
option(TRACY_NO_BROADCAST "Disable client discovery by broadcast to local network" OFF)
option(TRACY_NO_CODE_TRANSFER "Disable collection of source code" OFF)
option(TRACY_NO_CONTEXT_SWITCH "Disable capture of context switches" OFF)
option(TRACY_NO_EXIT "Client executable does not exit until all profile data is sent to server" OFF)
option(TRACY_NO_FRAME_IMAGE "Disable capture of frame images" OFF)
option(TRACE_NO_SAMPLING "Disable call stack sampling" OFF)
option(TRACY_NO_VERIFY "Disable zone validation for C API" OFF)
option(TRACY_NO_VSYNC_CAPTURE "Disable capture of hardware Vsync events" OFF)

add_library(TracyClient TracyClient.cpp)
target_compile_features(TracyClient PUBLIC cxx_std_11)
target_include_directories(TracyClient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(
    TracyClient
    PUBLIC
        Threads::Threads
        ${CMAKE_DL_LIBS}
)

if(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    find_library(EXECINFO_LIBRARY NAMES execinfo REQUIRED)
    target_link_libraries(TracyClient PUBLIC ${EXECINFO_LIBRARY})
endif()

add_library(Tracy::TracyClient ALIAS TracyClient)

macro(set_option OPTION)
    if(${OPTION})
        message(STATUS "${OPTION}: ON")
        target_compile_definitions(TracyClient PUBLIC ${OPTION})
    else()
        message(STATUS "${OPTION}: OFF")
    endif()
endmacro()

set_option(TRACY_ENABLE)
set_option(TRACY_ON_DEMAND)
set_option(TRACY_CALLSTACK)
set_option(TRACY_ONLY_LOCALHOST)
set_option(TRACY_NO_BROADCAST)
set_option(TRACY_NO_CODE_TRANSFER)
set_option(TRACY_NO_CONTEXT_SWITCH)
set_option(TRACY_NO_EXIT)
set_option(TRACY_NO_FRAME_IMAGE)
set_option(TRACE_NO_SAMPLING)
set_option(TRACY_NO_VERIFY)
set_option(TRACY_NO_VSYNC_CAPTURE)
