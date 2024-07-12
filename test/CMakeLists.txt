cmake_minimum_required(VERSION 3.16)

option(USE_DEBUGINFOD "Compile with debuginfod integration" ON)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/version.cmake)

# we target C++11 for the client part
set(CMAKE_CXX_STANDARD 11)

project(
  tracy-test
  LANGUAGES C CXX
  VERSION ${TRACY_VERSION_STRING})

file(GENERATE OUTPUT .gitignore CONTENT "*")

# a bit weird but works: include the client cmake config coming from top-level
# cmake needs us to specify the build subfolder -> client/ this way we can
# simply link the test executable against TracyClient
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/.. client/)

add_executable(tracy-test test.cpp)
target_link_options(tracy-test PRIVATE -rdynamic)
target_link_libraries(tracy-test TracyClient)

# OS-specific options

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND USE_DEBUGINFOD)
  target_compile_definitions(tracy-test PRIVATE TRACY_DEBUGINFOD)
  target_link_libraries(tracy-test "debuginfod")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  target_link_libraries(tracy-test "execinfo")
endif()


# copy image file in build folder
configure_file(${CMAKE_CURRENT_LIST_DIR}/image.jpg image.jpg COPYONLY)
