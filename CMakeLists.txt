cmake_minimum_required(VERSION 3.0)

project(tracy)

set(CMAKE_CXX_STANDARD 11)

option(TRACY_ENABLE "Profiling is enabled" ON)
option(TRACY_ON_DEMAND "Profiling enabled on demand" OFF)
option(TRACY_NO_EXIT "Client executable does not exit until all profile data is sent to server" OFF)
option(TRACY_NO_BROADCAST "Disable client discovery by broadcast to local network" OFF)

add_library(tracy_client TracyClient.cpp)

macro(set_option OPTION)
    if(${OPTION})
        message(STATUS "${OPTION}: ON")
        target_compile_definitions(tracy_client PUBLIC ${OPTION})
    else()
        message(STATUS "${OPTION}: OFF")
    endif()
endmacro()

set_option(TRACY_ENABLE)
set_option(TRACY_ON_DEMAND)
set_option(TRACY_NO_EXIT)
set_option(TRACY_NO_BROADCAST)
set_option(TRACY_USE_CONSTEXPR_VARIABLES)

if(NOT TRACY_PORT)
    set(TRACY_PORT 8086)
endif()

message(STATUS "TRACY_PORT: ${TRACY_PORT}")
target_compile_definitions(tracy_client PUBLIC TRACY_PORT=${TRACY_PORT})

target_include_directories(tracy_client PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

if (UNIX)
    target_link_libraries(tracy_client PRIVATE ${CMAKE_DL_LIBS})
endif()
