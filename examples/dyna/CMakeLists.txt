cmake_minimum_required(VERSION 3.29)
project(dyna LANGUAGES C CXX)

option(TRACY_ENABLE "Enable Tracy" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_COLOR_DIAGNOSTICS ON)

include(cmake/CPM.cmake)

CPMAddPackage(
  NAME glad
  VERSION 2.0.8
  GIT_REPOSITORY https://github.com/Dav1dde/glad.git
  GIT_TAG glad2
)

add_subdirectory(${glad_SOURCE_DIR}/cmake ${CMAKE_CURRENT_BINARY_DIR}/glad)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. client/)

glad_add_library(glad_gl_core_33 STATIC API gl:core=3.3)

find_package(SDL3 REQUIRED)
find_package(SDL3_image REQUIRED)

add_executable(dyna
  src/main.cpp
  src/datapath.cpp
  src/timer.cpp
  src/gfx.cpp
  src/texture.cpp
  src/entity.cpp
  src/world.cpp
  src/map.cpp
  src/player.cpp
  src/monster.cpp
  src/bomb.cpp
  src/bonus.cpp
  src/game.cpp
)

target_link_libraries(dyna
  PRIVATE
    glad_gl_core_33
    SDL3::SDL3
    SDL3_image::SDL3_image
    Tracy::TracyClient
)

target_include_directories(dyna PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Mirror the data/ tree next to the executable so the game finds its assets
# when launched from the build directory (paths are resolved via SDL_GetBasePath).
add_custom_command(TARGET dyna POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          ${CMAKE_CURRENT_SOURCE_DIR}/data
          $<TARGET_FILE_DIR:dyna>/data
  COMMENT "Copying data/ next to dyna executable"
)

file(GENERATE OUTPUT .gitignore CONTENT "*")
