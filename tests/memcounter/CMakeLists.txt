cmake_minimum_required(VERSION 3.16)

project(
    memcounter-test

    LANGUAGES CXX
)

enable_testing()

file(GENERATE OUTPUT .gitignore CONTENT "*")
set(CMAKE_CXX_STANDARD 20)

add_executable(
    memcounter-test
    test.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../server/TracyMemory.cpp
)

target_include_directories(
    memcounter-test
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../../server
)

add_test(NAME memcounter-test COMMAND memcounter-test)
