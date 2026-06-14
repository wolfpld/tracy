# CMakeLists.txt — OpenGL spinning triangle demo
#
#   macOS:
#     cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -B build/ninja .
#     cmake --build build/ninja
#
#   Linux (requires libsdl3-dev libgl1-mesa-dev):
#     cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -B build/ninja .
#     cmake --build build/ninja
#
#   Windows:
#     cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -B build/ninja .
#     cmake --build build/ninja

cmake_minimum_required(VERSION 3.16)
project(gl_spinning_triangle LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Tracy root — defaults to three directories above this CMakeLists.txt.
# ---------------------------------------------------------------------------
set(TRACY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
option(TRACY_ENABLE                  "Enable Tracy profiling"                    ON)

# ---------------------------------------------------------------------------
# Platform — SDL3 (cross-platform windowing, must be installed on the system)
# ---------------------------------------------------------------------------
find_package(SDL3 REQUIRED)

# ---------------------------------------------------------------------------
# GL extension loader — GLEW (Windows + Linux, fetched automatically)
# ---------------------------------------------------------------------------
if(NOT APPLE)
    include(FetchContent)
    set(glew-cmake_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(ONLY_LIBS               ON  CACHE BOOL "" FORCE)
    FetchContent_Declare(glew
        GIT_REPOSITORY https://github.com/Perlmint/glew-cmake.git
        GIT_TAG        master   # pin to a specific commit for reproducible builds
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(glew)
endif()

set(PLATFORM_SOURCES  platform/platform_sdl3.cpp)

if(APPLE)
    set(PLATFORM_LIBS SDL3::SDL3 "-framework OpenGL")
elseif(WIN32)
    set(PLATFORM_LIBS SDL3::SDL3 opengl32 libglew_static)
else()
    set(PLATFORM_LIBS SDL3::SDL3 GL libglew_static)
endif()

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
add_executable(gl_spinning_triangle
    spinning_triangle.cpp
    "${TRACY_DIR}/public/TracyClient.cpp"
    ${PLATFORM_SOURCES}
)

# Suppress upstream warnings from TracyClient.cpp
if(MSVC)
    set_source_files_properties("${TRACY_DIR}/public/TracyClient.cpp"
        PROPERTIES COMPILE_FLAGS "/w"
    )
else()
    set_source_files_properties("${TRACY_DIR}/public/TracyClient.cpp"
        PROPERTIES COMPILE_FLAGS "-w"
    )
endif()

target_compile_features(gl_spinning_triangle PRIVATE cxx_std_17)

if(TRACY_ENABLE)
    target_compile_definitions(gl_spinning_triangle PRIVATE TRACY_ENABLE)
endif()

target_include_directories(gl_spinning_triangle PRIVATE
    "${TRACY_DIR}/public"
)
target_link_libraries(gl_spinning_triangle PRIVATE ${PLATFORM_LIBS})
