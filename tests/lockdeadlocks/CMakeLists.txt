cmake_minimum_required(VERSION 3.16)

project(
    lockdeadlocks-test

    LANGUAGES C CXX
)

enable_testing()

file(GENERATE OUTPUT .gitignore CONTENT "*")
set(CMAKE_CXX_STANDARD 20)

# server headers pull in ppqsort through TracySort.hpp; reuse the CPM checkout when available
if(NOT PPQSORT_INCLUDE_DIR)
    file(GLOB PPQSORT_INCLUDE_DIR "$ENV{HOME}/.cache/cpm/ppqsort/*/include")
endif()

add_executable(
    lockdeadlocks-test
    test.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../server/TracyLocks.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../server/TracyMemory.cpp
)

target_include_directories(
    lockdeadlocks-test
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../../server
    ${CMAKE_CURRENT_LIST_DIR}/../../public/common
    ${PPQSORT_INCLUDE_DIR}
)

add_test(NAME lockdeadlocks-test COMMAND lockdeadlocks-test)
