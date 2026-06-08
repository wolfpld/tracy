cmake_minimum_required(VERSION 3.18)
project(CUDAGraphDemo LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_STANDARD 17)

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
    set(CMAKE_CUDA_ARCHITECTURES native)
endif()

set(TRACY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../.."
    CACHE PATH "Root of the Tracy repository")
set(TRACY_PUBLIC "${TRACY_PATH}/public")

find_package(CUDAToolkit REQUIRED)
find_package(Threads REQUIRED)

# cuda-graph-demo.cu embeds Tracy via #include <TracyClient.cpp> (unity build),
# so no separate TracyClient library is needed — just expose the public headers.
add_executable(cuda-graph-demo cuda-graph-demo.cu)
target_include_directories(cuda-graph-demo PRIVATE ${TRACY_PUBLIC})
target_link_libraries(cuda-graph-demo PRIVATE
    CUDA::cupti CUDA::cuda_driver Threads::Threads ${CMAKE_DL_LIBS})

# ctest-related integration below
# to run the binaries via ctest:
# ctest --test-dir <cmake-build-dir> -R <binary-name> -C <build-config>

enable_testing()
add_test(NAME cuda-graph-demo COMMAND cuda-graph-demo)

# On Windows, CUPTI's DLL must be on PATH at runtime.
if(WIN32)
    set(_cupti_dir "$<TARGET_FILE_DIR:CUDA::cupti>")
    set_target_properties(cuda-graph-demo PROPERTIES
        VS_DEBUGGER_ENVIRONMENT "PATH=${_cupti_dir};$ENV{PATH}")
    set_tests_properties(cuda-graph-demo PROPERTIES
        ENVIRONMENT "PATH=${_cupti_dir};$ENV{PATH}")
endif()
