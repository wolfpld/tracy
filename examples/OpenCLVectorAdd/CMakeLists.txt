cmake_minimum_required(VERSION 3.10)

project(OpenCLVectorAdd)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_package(OpenCL REQUIRED)

add_executable(OpenCLVectorAdd OpenCLVectorAdd.cpp)

add_library(TracyClient STATIC ../../public/TracyClient.cpp
                               ../../public/tracy/TracyOpenCL.hpp)
target_include_directories(TracyClient PUBLIC ../../public/tracy)
target_compile_definitions(TracyClient PUBLIC TRACY_ENABLE=1)

target_link_libraries(OpenCLVectorAdd PUBLIC OpenCL::OpenCL TracyClient ${CMAKE_DL_LIBS} Threads::Threads)
