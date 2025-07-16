cmake_minimum_required(VERSION 3.16)

set(CMAKE_CXX_STANDARD 20)

project(helpers LANGUAGES CXX)

add_executable(embed
    ../../public/common/tracy_lz4.cpp
    ../../public/common/tracy_lz4hc.cpp
    embed.cpp
)

install(TARGETS embed DESTINATION .)