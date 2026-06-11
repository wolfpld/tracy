# CMakeLists.txt — OpenGL spinning triangle demo
#
#   macOS:
#     cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -B build/ninja .
#     cmake --build build/ninja
#
#   Linux (requires libx11-dev libgl1-mesa-dev libglew-dev):
#     cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -B build/ninja .
#     cmake --build build/ninja
#
#   Windows (MSVC, requires GLEW):
#     cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DGLEW_ROOT=<path> -B build/ninja .
#     cmake --build build/ninja

cmake_minimum_required(VERSION 3.16)
project(gl_spinning_triangle LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Tracy root — defaults to three directories above this CMakeLists.txt.
# ---------------------------------------------------------------------------
set(TRACY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
option(TRACY_ENABLE                  "Enable Tracy profiling"                    ON)
option(TRACY_OPENGL_AUTO_CALIBRATION "Enable periodic GPU/CPU recalibration"     ON)

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

set(PLATFORM_SOURCES  platform/platform_rgfw.cpp)
set(PLATFORM_INCLUDES ${rgfw_SOURCE_DIR})

if(APPLE)
    set(PLATFORM_LIBS "-framework Cocoa" "-framework OpenGL"
                      "-framework CoreVideo" "-framework IOKit")
elseif(WIN32)
    find_package(GLEW REQUIRED)
    set(PLATFORM_LIBS opengl32 user32 gdi32 GLEW::GLEW)
else()
    find_package(GLEW REQUIRED)
    find_package(X11  REQUIRED)
    set(PLATFORM_LIBS X11::X11 GL GLEW::GLEW)
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
if(TRACY_OPENGL_AUTO_CALIBRATION)
    target_compile_definitions(gl_spinning_triangle PRIVATE TRACY_OPENGL_AUTO_CALIBRATION)
endif()

target_include_directories(gl_spinning_triangle PRIVATE
    "${TRACY_DIR}/public"
    ${PLATFORM_INCLUDES}
)
target_link_libraries(gl_spinning_triangle PRIVATE ${PLATFORM_LIBS})
