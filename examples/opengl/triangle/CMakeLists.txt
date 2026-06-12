# CMakeLists.txt — OpenGL spinning triangle demo
#
#   macOS:
#     cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -B build/ninja .
#     cmake --build build/ninja
#
#   Linux (requires libx11-dev libgl1-mesa-dev):
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
# Platform — RGFW (cross-platform windowing, fetched automatically)
# ---------------------------------------------------------------------------
include(FetchContent)
FetchContent_Declare(rgfw
    GIT_REPOSITORY https://github.com/ColleagueRiley/RGFW.git
    GIT_TAG        main   # pin to a specific commit for reproducible builds
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(rgfw)

# ---------------------------------------------------------------------------
# GL extension loader — GLEW (Windows + Linux, fetched automatically)
# ---------------------------------------------------------------------------
if(NOT APPLE)
    set(glew-cmake_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(ONLY_LIBS               ON  CACHE BOOL "" FORCE)
    FetchContent_Declare(glew
        GIT_REPOSITORY https://github.com/Perlmint/glew-cmake.git
        GIT_TAG        master   # pin to a specific commit for reproducible builds
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(glew)
endif()

set(PLATFORM_SOURCES  platform/platform_rgfw.cpp)
set(PLATFORM_INCLUDES ${rgfw_SOURCE_DIR})

if(APPLE)
    set(PLATFORM_LIBS "-framework Cocoa" "-framework OpenGL"
                      "-framework CoreVideo" "-framework IOKit")
elseif(WIN32)
    set(PLATFORM_LIBS opengl32 user32 gdi32 libglew_static)
else()
    find_package(X11 REQUIRED)
    if(NOT X11_Xrandr_FOUND)
        message(FATAL_ERROR "Xrandr not found — install libxrandr-dev")
    endif()
    set(PLATFORM_LIBS X11::X11 X11::Xrandr GL libglew_static)
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
    ${PLATFORM_INCLUDES}
)
target_link_libraries(gl_spinning_triangle PRIVATE ${PLATFORM_LIBS})
