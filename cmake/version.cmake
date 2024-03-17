cmake_minimum_required(VERSION 3.10)

message("Parsing public/common/TracyVersion.hpp file")

file(READ "${CMAKE_CURRENT_LIST_DIR}/../public/common/TracyVersion.hpp" version)

# Note: This looks for a specific pattern in TracyVersion.hpp, if it changes
# this needs updating.
string(REGEX MATCH "Major = ([0-9]+)" _ ${version})

# This works do to the above () subexpression selection. See
# https://cmake.org/cmake/help/latest/command/string.html#regex-match for more
# details
set(TRACY_VERSION_MAJOR ${CMAKE_MATCH_1})

string(REGEX MATCH "Minor = ([0-9]+)" _ ${version})
set(TRACY_VERSION_MINOR ${CMAKE_MATCH_1})

string(REGEX MATCH "Patch = ([0-9]+)" _ ${version})
set(TRACY_VERSION_PATCH ${CMAKE_MATCH_1})

set(TRACY_VERSION_STRING "${TRACY_VERSION_MAJOR}.${TRACY_VERSION_MINOR}.${TRACY_VERSION_PATCH}")

message("VERSION ${TRACY_VERSION_STRING}")
