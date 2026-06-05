cmake_minimum_required(VERSION 3.25)
project(CUDAGraphReproTests LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_ARCHITECTURES native)

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
