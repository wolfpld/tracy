cmake_minimum_required(VERSION 3.10)

# Run version helper script
include(cmake/version.cmake)

project(Tracy LANGUAGES CXX VERSION ${TRACY_VERSION_STRING})

file(GENERATE OUTPUT .gitignore CONTENT "*")

if(${BUILD_SHARED_LIBS})
    set(DEFAULT_STATIC OFF)
else()
    set(DEFAULT_STATIC ON)
endif()

option(TRACY_STATIC "Whether to build Tracy as a static library" ${DEFAULT_STATIC})
option(TRACY_Fortran "Build Fortran bindings" OFF)
option(TRACY_LTO "Enable Link-Time optimization" OFF)

if(TRACY_Fortran)
  enable_language(Fortran)
  set(CMAKE_Fortran_VERSION 2003)
endif()

if(TRACY_LTO OR CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT LTO_SUPPORTED)
    if(NOT LTO_SUPPORTED)
        message(WARNING "LTO is not supported!")
    endif()
else()
    set(LTO_SUPPORTED OFF)
endif()

find_package(Threads REQUIRED)
find_package(rocprofiler-sdk PATHS "/opt/rocm/lib/cmake")

set(TRACY_PUBLIC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/public)

if(LTO_SUPPORTED)
    set(TRACY_VISIBILITY "OBJECT")
elseif(TRACY_STATIC)
    set(TRACY_VISIBILITY "STATIC")
else()
    set(TRACY_VISIBILITY "SHARED")
endif()

add_library(TracyClient ${TRACY_VISIBILITY} "${TRACY_PUBLIC_DIR}/TracyClient.cpp")
target_compile_features(TracyClient PUBLIC cxx_std_11)
set_target_properties(TracyClient PROPERTIES INTERPROCEDURAL_OPTIMIZATION ${LTO_SUPPORTED})
target_include_directories(TracyClient SYSTEM PUBLIC
    $<BUILD_INTERFACE:${TRACY_PUBLIC_DIR}>
    $<INSTALL_INTERFACE:include/tracy>)
target_link_libraries(
    TracyClient
    PUBLIC
        Threads::Threads
        ${CMAKE_DL_LIBS}
)
if(rocprofiler-sdk_FOUND)
    target_compile_definitions(TracyClient PUBLIC TRACY_ROCPROF)
    target_link_libraries(TracyClient PUBLIC rocprofiler-sdk::rocprofiler-sdk)
endif()

if(TRACY_Fortran)
    add_library(TracyClientF90 ${TRACY_VISIBILITY} "${TRACY_PUBLIC_DIR}/TracyClient.F90")
    target_include_directories(TracyClientF90 PUBLIC
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
        $<INSTALL_INTERFACE:include/tracy>)
    target_link_libraries(
        TracyClientF90
        PUBLIC
            TracyClient
    )
    set_target_properties(TracyClientF90 PROPERTIES Fortran_MODULE_DIRECTORY ${PROJECT_BINARY_DIR}
                                                    INTERPROCEDURAL_OPTIMIZATION ${LTO_SUPPORTED})
endif()

# Public dependency on some libraries required when using Mingw
if(WIN32 AND ${CMAKE_CXX_COMPILER_ID} MATCHES "GNU|Clang")
    target_link_libraries(TracyClient PUBLIC ws2_32 dbghelp secur32)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    find_library(EXECINFO_LIBRARY NAMES execinfo REQUIRED)
    target_link_libraries(TracyClient PUBLIC ${EXECINFO_LIBRARY})
endif()

if(TRACY_LIBUNWIND_BACKTRACE)
    include(FindPkgConfig)
    pkg_check_modules(unwind REQUIRED libunwind)
    target_include_directories(TracyClient INTERFACE ${unwind_INCLUDE_DIRS})
    target_link_libraries(TracyClient INTERFACE ${unwind_LINK_LIBRARIES})
endif()

if(TRACY_DEBUGINFOD)
    include(FindPkgConfig)
    pkg_check_modules(debuginfod REQUIRED libdebuginfod)
    target_include_directories(TracyClient INTERFACE ${debuginfod_INCLUDE_DIRS})
    target_link_libraries(TracyClient INTERFACE ${debuginfod_LINK_LIBRARIES})
endif()

add_library(Tracy::TracyClient ALIAS TracyClient)
if(TRACY_Fortran)
    add_library(Tracy::TracyClient_Fortran ALIAS TracyClientF90)
endif()

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
set_option(TRACY_CALLSTACK "Enforce callstack collection for tracy regions" OFF)
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
set_option(TRACY_PATCHABLE_NOPSLEDS  "Enable nopsleds for efficient patching by system-level tools (e.g. rr)" OFF)
set_option(TRACY_DELAYED_INIT "Enable delayed initialization of the library (init on first call)" OFF)
set_option(TRACY_MANUAL_LIFETIME "Enable the manual lifetime management of the profile" OFF)
set_option(TRACY_FIBERS "Enable fibers support" OFF)
set_option(TRACY_NO_CRASH_HANDLER "Disable crash handling" OFF)
set_option(TRACY_TIMER_FALLBACK "Use lower resolution timers" OFF)
set_option(TRACY_DISALLOW_HW_TIMER  "Disallow hardware timer (may be useful on VMs). Requires TRACY_TIMER_FALLBACK=ON" OFF)
set_option(TRACY_LIBUNWIND_BACKTRACE "Use libunwind backtracing where supported" OFF)
set_option(TRACY_SYMBOL_OFFLINE_RESOLVE "Instead of full runtime symbol resolution, only resolve the image path and offset to enable offline symbol resolution" OFF)
set_option(TRACY_LIBBACKTRACE_ELF_DYNLOAD_SUPPORT "Enable libbacktrace to support dynamically loaded elfs in symbol resolution resolution after the first symbol resolve operation" OFF)
set_option(TRACY_DEBUGINFOD "Enable debuginfod support" OFF)
set_option(TRACY_IGNORE_MEMORY_FAULTS "Ignore instrumentation errors from memory free events that do not have a matching allocation" OFF)

# advanced
set_option(TRACY_VERBOSE "[advanced] Verbose output from the profiler" OFF)
mark_as_advanced(TRACY_VERBOSE)
set_option(TRACY_NO_INTERNAL_MESSAGE "[advanced] Prevent the profiler from logging messages" OFF)
mark_as_advanced(TRACY_NO_INTERNAL_MESSAGE)
set_option(TRACY_DEMANGLE "[advanced] Don't use default demangling function - You'll need to provide your own" OFF)
mark_as_advanced(TRACY_DEMANGLE)
if(rocprofiler-sdk_FOUND)
    set_option(TRACY_ROCPROF_CALIBRATION "[advanced] Use continuous calibration of the Rocprof GPU time." OFF)
    mark_as_advanced(TRACY_ROCPROF_CALIBRATION)
endif()

# handle incompatible combinations
if(TRACY_MANUAL_LIFETIME AND NOT TRACY_DELAYED_INIT)
    message(FATAL_ERROR "TRACY_MANUAL_LIFETIME can not be activated with disabled TRACY_DELAYED_INIT")
endif()
if(TRACY_DISALLOW_HW_TIMER AND NOT TRACY_TIMER_FALLBACK)
    message(FATAL_ERROR "TRACY_DISALLOW_HW_TIMER can not be activated with disabled TRACY_TIMER_FALLBACK")
endif()

if(NOT TRACY_STATIC)
    target_compile_definitions(TracyClient PRIVATE TRACY_EXPORTS)
    target_compile_definitions(TracyClient PUBLIC TRACY_IMPORTS)
endif()

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set_target_properties(TracyClient PROPERTIES VERSION ${PROJECT_VERSION})
if(TRACY_Fortran)
    set_target_properties(TracyClientF90 PROPERTIES VERSION ${PROJECT_VERSION})
endif()

set(tracy_includes
    ${TRACY_PUBLIC_DIR}/tracy/TracyC.h
    ${TRACY_PUBLIC_DIR}/tracy/Tracy.hpp
    ${TRACY_PUBLIC_DIR}/tracy/TracyCUDA.hpp
    ${TRACY_PUBLIC_DIR}/tracy/TracyD3D11.hpp
    ${TRACY_PUBLIC_DIR}/tracy/TracyD3D12.hpp
    ${TRACY_PUBLIC_DIR}/tracy/TracyLua.hpp
    ${TRACY_PUBLIC_DIR}/tracy/TracyMetal.hmm
    ${TRACY_PUBLIC_DIR}/tracy/TracyOpenCL.hpp
    ${TRACY_PUBLIC_DIR}/tracy/TracyOpenGL.hpp
    ${TRACY_PUBLIC_DIR}/tracy/TracyVulkan.hpp)

set(client_includes
    ${TRACY_PUBLIC_DIR}/client/tracy_concurrentqueue.h
    ${TRACY_PUBLIC_DIR}/client/tracy_rpmalloc.hpp
    ${TRACY_PUBLIC_DIR}/client/tracy_SPSCQueue.h
    ${TRACY_PUBLIC_DIR}/client/TracyKCore.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyArmCpuTable.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyCallstack.h
    ${TRACY_PUBLIC_DIR}/client/TracyCallstack.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyCpuid.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyDebug.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyDxt1.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyFastVector.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyLock.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyProfiler.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyRingBuffer.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyScoped.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyStringHelpers.hpp
    ${TRACY_PUBLIC_DIR}/client/TracySysPower.hpp
    ${TRACY_PUBLIC_DIR}/client/TracySysTime.hpp
    ${TRACY_PUBLIC_DIR}/client/TracySysTrace.hpp
    ${TRACY_PUBLIC_DIR}/client/TracyThread.hpp)

set(common_includes
    ${TRACY_PUBLIC_DIR}/common/tracy_lz4.hpp
    ${TRACY_PUBLIC_DIR}/common/tracy_lz4hc.hpp
    ${TRACY_PUBLIC_DIR}/common/TracyAlign.hpp
    ${TRACY_PUBLIC_DIR}/common/TracyAlloc.hpp
    ${TRACY_PUBLIC_DIR}/common/TracyApi.h
    ${TRACY_PUBLIC_DIR}/common/TracyColor.hpp
    ${TRACY_PUBLIC_DIR}/common/TracyForceInline.hpp
    ${TRACY_PUBLIC_DIR}/common/TracyMutex.hpp
    ${TRACY_PUBLIC_DIR}/common/TracyProtocol.hpp
    ${TRACY_PUBLIC_DIR}/common/TracyQueue.hpp
    ${TRACY_PUBLIC_DIR}/common/TracySocket.hpp
    ${TRACY_PUBLIC_DIR}/common/TracyStackFrames.hpp
    ${TRACY_PUBLIC_DIR}/common/TracySystem.hpp
    ${TRACY_PUBLIC_DIR}/common/TracyWinFamily.hpp
    ${TRACY_PUBLIC_DIR}/common/TracyYield.hpp)

install(TARGETS TracyClient
        EXPORT TracyConfig
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}/$<IF:$<CONFIG:Release>,,$<CONFIG>>
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}/$<IF:$<CONFIG:Release>,,$<CONFIG>>
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}/$<IF:$<CONFIG:Release>,,$<CONFIG>>
        COMPONENT lib)
if(TRACY_Fortran)
    install(TARGETS TracyClientF90
            EXPORT TracyConfig
            RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}/$<IF:$<CONFIG:Release>,,$<CONFIG>>
            LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}/$<IF:$<CONFIG:Release>,,$<CONFIG>>
            ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}/$<IF:$<CONFIG:Release>,,$<CONFIG>>
            COMPONENT lib)
endif()
# Export targets to build tree root
export(TARGETS TracyClient
       NAMESPACE Tracy::
       FILE ${CMAKE_BINARY_DIR}/TracyTargets.cmake)
if(TRACY_Fortran)
    export(TARGETS TracyClientF90
           NAMESPACE Tracy::
           APPEND
           FILE ${CMAKE_BINARY_DIR}/TracyTargets.cmake)
endif()
install(FILES ${tracy_includes}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tracy/tracy)
install(FILES ${client_includes}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tracy/client)
install(FILES ${common_includes}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tracy/common)
if(TRACY_Fortran)
    if(${CMAKE_Fortran_COMPILER_ID} MATCHES "Cray")
        install(FILES ${PROJECT_BINARY_DIR}/TRACY.mod
                DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tracy)
    else()
        install(FILES ${PROJECT_BINARY_DIR}/tracy.mod
                DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tracy)
    endif()
endif()
install(EXPORT TracyConfig
        NAMESPACE Tracy::
        FILE TracyTargets.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
include(CMakePackageConfigHelpers)
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/TracyConfig.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/TracyConfig.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

option(TRACY_CLIENT_PYTHON "Whether to build Tracy python client library" OFF)

if(TRACY_CLIENT_PYTHON)
    if(TRACY_STATIC)
        message(FATAL_ERROR "Python-bindings require a shared client library")
    endif()

    add_subdirectory(python)
endif()
