cmake_minimum_required(VERSION 3.18)
project(CUDAGraphReproTests LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_STANDARD 17)

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
    set(CMAKE_CUDA_ARCHITECTURES native)
endif()

set(TRACY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../../.."
    CACHE PATH "Root of the Tracy repository")
set(TRACY_PUBLIC "${TRACY_PATH}/public")

option(TRACY_ENABLE "Enable profiling" ON)

find_package(CUDAToolkit REQUIRED)
find_package(Threads REQUIRED)

# Tracy client (CXX-only, matching the Makefile's g++ step for TracyClient.cpp)
add_library(TracyClient STATIC ${TRACY_PUBLIC}/TracyClient.cpp)
target_include_directories(TracyClient PUBLIC ${TRACY_PUBLIC})
target_link_libraries(TracyClient PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
if(TRACY_ENABLE)
    target_compile_definitions(TracyClient PUBLIC TRACY_ENABLE)
endif()

# repro: Tracy-integrated CUDA Graph reproducer
add_executable(repro repro.cu)
target_link_libraries(repro PRIVATE TracyClient CUDA::cupti CUDA::cuda_driver)

# Standalone CUPTI probes (no Tracy dependency)
add_executable(test_corr_reuse test_corr_reuse.cu)
target_link_libraries(test_corr_reuse PRIVATE CUDA::cupti CUDA::cuda_driver)

add_executable(test_graphid_recycle test_graphid_recycle.cu)
target_link_libraries(test_graphid_recycle PRIVATE CUDA::cupti CUDA::cuda_driver)

set(_all_targets repro test_corr_reuse test_graphid_recycle)

# ctest-related integration below
# to run the binaries via ctest:
# ctest --test-dir <cmake-build-dir> -R <binary-name> -C <build-config>

enable_testing()
foreach(_target ${_all_targets})
    add_test(NAME ${_target} COMMAND ${_target})
endforeach()

# On Windows, CUPTI's DLL must be on PATH at runtime.
# Propagate the DLL directory to both the VS debugger and ctest.
if(WIN32)
    set(_cupti_dir "$<TARGET_FILE_DIR:CUDA::cupti>")
    foreach(_target ${_all_targets})
        set_target_properties(${_target} PROPERTIES
            VS_DEBUGGER_ENVIRONMENT "PATH=${_cupti_dir};$ENV{PATH}")
        set_tests_properties(${_target} PROPERTIES
            ENVIRONMENT "PATH=${_cupti_dir};$ENV{PATH}")
    endforeach()
endif()
