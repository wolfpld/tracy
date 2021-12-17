cmake_minimum_required(VERSION 3.10)

project(Tracy LANGUAGES CXX)

find_package(Threads REQUIRED)

add_library(TracyClient TracyClient.cpp)
target_compile_features(TracyClient PUBLIC cxx_std_11)
target_include_directories(TracyClient SYSTEM PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}> 
    $<INSTALL_INTERFACE:include>)
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

macro(set_option option help value)
    option(${option} ${help} ${value})
    if(${option})
        message(STATUS "${option}: ON")
        target_compile_definitions(TracyClient PUBLIC ${option})
    else()
        message(STATUS "${option}: OFF")
    endif()
endmacro()

set_option(TRACY_ENABLE "Enable profiling" ON)
set_option(TRACY_ON_DEMAND "On-demand profiling" OFF)
set_option(TRACY_CALLSTACK "Collect call stacks" OFF)
set_option(TRACY_ONLY_LOCALHOST "Only listen on the localhost interface" OFF)
set_option(TRACY_NO_BROADCAST "Disable client discovery by broadcast to local network" OFF)
set_option(TRACY_NO_CODE_TRANSFER "Disable collection of source code" OFF)
set_option(TRACY_NO_CONTEXT_SWITCH "Disable capture of context switches" OFF)
set_option(TRACY_NO_EXIT "Client executable does not exit until all profile data is sent to server" OFF)
set_option(TRACY_NO_FRAME_IMAGE "Disable capture of frame images" OFF)
set_option(TRACE_NO_SAMPLING "Disable call stack sampling" OFF)
set_option(TRACY_NO_VERIFY "Disable zone validation for C API" OFF)
set_option(TRACY_NO_VSYNC_CAPTURE "Disable capture of hardware Vsync events" OFF)

if(BUILD_SHARED_LIBS)
    target_compile_definitions(TracyClient PRIVATE TRACY_EXPORTS)
    target_compile_definitions(TracyClient PUBLIC TRACY_IMPORTS)
endif()

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(includes
    ${CMAKE_CURRENT_LIST_DIR}/TracyC.h
    ${CMAKE_CURRENT_LIST_DIR}/Tracy.hpp
    ${CMAKE_CURRENT_LIST_DIR}/TracyD3D11.hpp
    ${CMAKE_CURRENT_LIST_DIR}/TracyD3D12.hpp
    ${CMAKE_CURRENT_LIST_DIR}/TracyLua.hpp
    ${CMAKE_CURRENT_LIST_DIR}/TracyOpenCL.hpp
    ${CMAKE_CURRENT_LIST_DIR}/TracyOpenGL.hpp
    ${CMAKE_CURRENT_LIST_DIR}/TracyVulkan.hpp)

install(TARGETS TracyClient
        EXPORT TracyConfig
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${includes}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT TracyConfig
        FILE TracyConfig.cmake
        DESTINATION share/Tracy)
