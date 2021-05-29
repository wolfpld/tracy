cmake_minimum_required(VERSION 3.10)
project(TracyClient LANGUAGES CXX)
add_library(TracyClient INTERFACE)
target_include_directories(TracyClient INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
