cmake_minimum_required(VERSION 3.0)

project(OpenCLVectorAdd)

find_package(OpenCL REQUIRED)

add_executable(OpenCLVectorAdd OpenCLVectorAdd.cpp)

add_library(TracyClient STATIC ../../TracyClient.cpp
                               ../../TracyOpenCL.hpp)
target_include_directories(TracyClient PUBLIC ../../)
target_compile_definitions(TracyClient PUBLIC TRACY_ENABLE=1)

target_link_libraries(OpenCLVectorAdd PUBLIC OpenCL::OpenCL TracyClient)
