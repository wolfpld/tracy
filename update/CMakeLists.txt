cmake_minimum_required(VERSION 3.16)

option(NO_ISA_EXTENSIONS "Disable ISA extensions (don't pass -march=native or -mcpu=native to the compiler)" OFF )
option(NO_STATISTICS "Disable calculation of statistics" ON)
option(LIBDW_OFFLINE_SYMBOL_RESOLUTION_SUPPORT "Suppport using libdw for offline symbol resolution." OFF)
option(LIBBACKTRACE_OFFLINE_SYMBOL_RESOLUTION_SUPPORT "Suppport using libbacktrace for offline symbol resolution." OFF)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/version.cmake)

set(CMAKE_CXX_STANDARD 20)

project(
    tracy-update
    LANGUAGES C CXX
    VERSION ${TRACY_VERSION_STRING}
)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/config.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/server.cmake)

set(PROGRAM_FILES
    src/OfflineSymbolResolver.cpp
    src/OfflineSymbolResolverAddr2Line.cpp
    src/OfflineSymbolResolverDbgHelper.cpp
    src/OfflineSymbolResolverLibdw.cpp
    src/OfflineSymbolResolverLibBacktrace.cpp
    src/update.cpp
)

add_executable(${PROJECT_NAME} ${PROGRAM_FILES} ${COMMON_FILES} ${SERVER_FILES})
target_link_libraries(${PROJECT_NAME} PRIVATE TracyServer TracyGetOpt)

if(LIBDW_OFFLINE_SYMBOL_RESOLUTION_SUPPORT)
    message("LIBDW_OFFLINE_SYMBOL_RESOLUTION_SUPPORT = ${LIBDW_OFFLINE_SYMBOL_RESOLUTION_SUPPORT}" )
    target_compile_definitions(${PROJECT_NAME} PRIVATE LIBDW_OFFLINE_SYMBOL_RESOLUTION_SUPPORT)
    # expects the requires libraries be installed in the target system
    target_link_libraries(${PROJECT_NAME} PRIVATE dl dw elf)
endif()
if(LIBBACKTRACE_OFFLINE_SYMBOL_RESOLUTION_SUPPORT)
    message("LIBBACKTRACE_OFFLINE_SYMBOL_RESOLUTION_SUPPORT = ${LIBBACKTRACE_OFFLINE_SYMBOL_RESOLUTION_SUPPORT}" )
    target_compile_definitions(${PROJECT_NAME} PRIVATE LIBBACKTRACE_OFFLINE_SYMBOL_RESOLUTION_SUPPORT)
    target_link_libraries(${PROJECT_NAME} PRIVATE backtrace)
endif()

set_property(DIRECTORY ${CMAKE_CURRENT_LIST_DIR} PROPERTY VS_STARTUP_PROJECT ${PROJECT_NAME})