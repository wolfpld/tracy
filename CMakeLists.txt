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

# Public dependency on some libraries required when using Mingw
if(WIN32 AND ${CMAKE_CXX_COMPILER_ID} MATCHES "GNU")
    target_link_libraries(TracyClient PUBLIC ws2_32 dbghelp)
endif()

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
set_option(TRACY_CALLSTACK "Enfore callstack collection for tracy regions" OFF)
set_option(TRACY_NO_CALLSTACK "Disable all callstack related functionality" OFF)
set_option(TRACY_NO_CALLSTACK_INLINES "Disables the inline functions in callstacks" OFF)
set_option(TRACY_ONLY_LOCALHOST "Only listen on the localhost interface" OFF)
set_option(TRACY_NO_BROADCAST "Disable client discovery by broadcast to local network" OFF)
set_option(TRACY_ONLY_IPV4 "Tracy will only accept connections on IPv4 addresses (disable IPv6)" OFF)
set_option(TRACY_NO_CODE_TRANSFER "Disable collection of source code" OFF)
set_option(TRACY_NO_CONTEXT_SWITCH "Disable capture of context switches" OFF)
set_option(TRACY_NO_EXIT "Client executable does not exit until all profile data is sent to server" OFF)
set_option(TRACY_NO_SAMPLING "Disable call stack sampling" OFF)
set_option(TRACY_NO_VERIFY "Disable zone validation for C API" OFF)
set_option(TRACY_NO_VSYNC_CAPTURE "Disable capture of hardware Vsync events" OFF)
set_option(TRACY_NO_FRAME_IMAGE  "Disable the frame image support and its thread" OFF)
set_option(TRACY_NO_SYSTEM_TRACING  "Disable systrace sampling" OFF)
set_option(TRACY_DELAYED_INIT "Enable delayed initialization of the library (init on first call)" OFF)
set_option(TRACY_MANUAL_LIFETIME "Enable the manual lifetime management of the profile" OFF)
set_option(TRACY_FIBERS "Enable fibers support" OFF)
set_option(TRACY_NO_CRASH_HANDLER "Disable crash handling" OFF)
set_option(TRACY_TIMER_FALLBACK "Use lower resolution timers" OFF)

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

set(client_includes
    ${CMAKE_CURRENT_LIST_DIR}/client/tracy_concurrentqueue.h
    ${CMAKE_CURRENT_LIST_DIR}/client/tracy_rpmalloc.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/tracy_SPSCQueue.h
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyArmCpuTable.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyCallstack.h
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyCallstack.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyDebug.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyDxt1.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyFastVector.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyLock.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyProfiler.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyRingBuffer.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyScoped.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyStringHelpers.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracySysTime.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracySysTrace.hpp
    ${CMAKE_CURRENT_LIST_DIR}/client/TracyThread.hpp)

set(common_includes
    ${CMAKE_CURRENT_LIST_DIR}/common/tracy_lz4.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/tracy_lz4hc.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyAlign.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyAlign.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyAlloc.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyApi.h
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyColor.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyForceInline.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyMutex.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyProtocol.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyQueue.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracySocket.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyStackFrames.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracySystem.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyUwp.hpp
    ${CMAKE_CURRENT_LIST_DIR}/common/TracyYield.hpp)

install(TARGETS TracyClient
        EXPORT TracyConfig
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${includes}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${client_includes}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/client)
install(FILES ${common_includes}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/common)
install(EXPORT TracyConfig
        NAMESPACE Tracy::
        FILE TracyConfig.cmake
        DESTINATION share/Tracy)
