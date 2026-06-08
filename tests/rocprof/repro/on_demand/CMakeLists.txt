cmake_minimum_required(VERSION 3.21)
project(RocprofOnDemandReproTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

set(TRACY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../../.."
    CACHE PATH "Root of the Tracy repository")
set(TRACY_PUBLIC "${TRACY_PATH}/public")

set(ROCM_PATH "/opt/rocm" CACHE PATH "Root of the ROCm installation")

# Locate hipcc so the HIP language can be enabled.
if(NOT DEFINED CMAKE_HIP_COMPILER)
    find_program(CMAKE_HIP_COMPILER hipcc HINTS "${ROCM_PATH}/bin")
endif()
enable_language(HIP)

find_package(Threads REQUIRED)

# rocprofiler-sdk: prefer the packaged config, fall back to a bare library
# search under ROCM_PATH (mirrors the original Makefile's -lrocprofiler-sdk).
find_library(ROCPROFILER_SDK_LIB rocprofiler-sdk HINTS "${ROCM_PATH}/lib")
if(NOT ROCPROFILER_SDK_LIB)
    message(FATAL_ERROR "Could not find librocprofiler-sdk under ${ROCM_PATH}/lib")
endif()

# Defines shared by the Tracy client and the reproducer. On-demand mode is
# the point of this repro: profiling starts when a client connects.
set(REPRO_DEFINES TRACY_ENABLE TRACY_ON_DEMAND TRACY_ROCPROF __HIP_PLATFORM_AMD__)

# Tracy client (built with the rocprof backend enabled).
add_library(TracyClient STATIC ${TRACY_PUBLIC}/TracyClient.cpp)
target_include_directories(TracyClient PUBLIC ${TRACY_PUBLIC} "${ROCM_PATH}/include")
target_compile_definitions(TracyClient PUBLIC ${REPRO_DEFINES})
target_link_libraries(TracyClient PUBLIC Threads::Threads ${CMAKE_DL_LIBS})

# repro: minimal HIP program that emits GPU zones via the rocprof backend.
add_executable(repro repro.cpp)
set_source_files_properties(repro.cpp PROPERTIES LANGUAGE HIP)
target_include_directories(repro PRIVATE "${ROCM_PATH}/include")
target_compile_definitions(repro PRIVATE ${REPRO_DEFINES})
target_link_libraries(repro PRIVATE TracyClient ${ROCPROFILER_SDK_LIB})

# check_gpu_ctx_name: loads a .tracy capture and verifies the GPU context
# name was deferred to (and received by) a late-connecting client. Links the
# Tracy server library, assembled the same way tracy-capture does it
# (cmake/server.cmake + vendor.cmake). Off by default since it pulls in the
# full server build and its vendored dependencies.
option(BUILD_CHECK_TOOL "Build the check_gpu_ctx_name verification helper" OFF)
if(BUILD_CHECK_TOOL)
    set(NO_STATISTICS ON)
    include(${TRACY_PATH}/cmake/vendor.cmake)
    include(${TRACY_PATH}/cmake/server.cmake)
    add_executable(check_gpu_ctx_name check_gpu_ctx_name.cpp)
    target_compile_features(check_gpu_ctx_name PRIVATE cxx_std_20)
    target_include_directories(check_gpu_ctx_name PRIVATE ${TRACY_PATH})
    target_link_libraries(check_gpu_ctx_name PRIVATE TracyServer)
endif()

# ctest integration. To run the binaries via ctest:
#   ctest --test-dir <cmake-build-dir> -R repro
enable_testing()
add_test(NAME repro COMMAND repro)
