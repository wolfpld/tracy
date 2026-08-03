cmake_minimum_required(VERSION 3.18)
project(CUDAOnDemandReproTests LANGUAGES C CXX CUDA)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CUDA_STANDARD 17)

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
    set(CMAKE_CUDA_ARCHITECTURES native)
endif()

set(TRACY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../../.."
    CACHE PATH "Root of the Tracy repository")
set(TRACY_PUBLIC "${TRACY_PATH}/public")

find_package(CUDAToolkit REQUIRED)
find_package(Threads REQUIRED)

# On-demand mode is the point of this repro: the client sits idle until a
# profiler connects, which is exactly what triggers the crash.
set(REPRO_DEFINES TRACY_ENABLE TRACY_ON_DEMAND)

# Tracy client (CXX-only, matching the Makefile's g++ step for TracyClient.cpp)
add_library(TracyClient STATIC ${TRACY_PUBLIC}/TracyClient.cpp)
target_include_directories(TracyClient PUBLIC ${TRACY_PUBLIC})
target_compile_definitions(TracyClient PUBLIC ${REPRO_DEFINES})
target_link_libraries(TracyClient PUBLIC Threads::Threads ${CMAKE_DL_LIBS})

# repro: minimal CUDA program that creates a CUDA context and emits GPU zones
add_executable(repro repro.cu)
target_link_libraries(repro PRIVATE TracyClient CUDA::cupti CUDA::cuda_driver)

# check_gpu_zones: loads a .tracy capture and verifies at least one GPU
# context was registered, named, and has recorded GPU zones. Links the
# Tracy server library, assembled the same way tracy-capture does it
# (cmake/server.cmake + vendor.cmake). Off by default since it pulls in the
# full server build and its vendored dependencies.
option(BUILD_CHECK_TOOL "Build the check_gpu_zones verification helper" OFF)
if(BUILD_CHECK_TOOL)
    set(NO_STATISTICS ON)
    include(${TRACY_PATH}/cmake/vendor.cmake)
    include(${TRACY_PATH}/cmake/server.cmake)
    add_executable(check_gpu_zones check_gpu_zones.cpp)
    target_compile_features(check_gpu_zones PRIVATE cxx_std_20)
    target_include_directories(check_gpu_zones PRIVATE ${TRACY_PATH})
    target_link_libraries(check_gpu_zones PRIVATE TracyServer)
endif()

# ctest integration. To run the binaries via ctest:
#   ctest --test-dir <cmake-build-dir> -R repro -C <build-config>
enable_testing()
add_test(NAME repro COMMAND repro)
