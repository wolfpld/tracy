cmake_minimum_required(VERSION 3.10)

set(ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

message("Parsing public/common/TracyVersion.hpp file")

file(READ "${ROOT_DIR}/public/common/TracyVersion.hpp" version)

# Note: This looks for a specific pattern in TracyVersion.hpp, if it changes
# this needs updating.
string(REGEX MATCH "Major = ([0-9]+)" _ ${version})

# This works do to the above () subexpression selection. See
# https://cmake.org/cmake/help/latest/command/string.html#regex-match for more
# details
set(major ${CMAKE_MATCH_1})

string(REGEX MATCH "Minor = ([0-9]+)" _ ${version})
set(minor ${CMAKE_MATCH_1})

string(REGEX MATCH "Patch = ([0-9]+)" _ ${version})
set(patch ${CMAKE_MATCH_1})

message("VERSION ${major}.${minor}.${patch}")
