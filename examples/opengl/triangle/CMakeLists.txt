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
# Platform-specific sources and link settings
# ---------------------------------------------------------------------------
if(APPLE)
    set(PLATFORM_SOURCES platform/platform_macos.mm)
    set(PLATFORM_LIBS "-framework Cocoa" "-framework OpenGL")
    set_source_files_properties(platform/platform_macos.mm
        PROPERTIES COMPILE_FLAGS "-ObjC++"
    )
elseif(WIN32)
    find_package(GLEW REQUIRED)
    set(PLATFORM_SOURCES platform/platform_windows.cpp)
    set(PLATFORM_LIBS opengl32 GLEW::GLEW)
else()
    find_package(GLEW REQUIRED)
    find_package(X11  REQUIRED)
    set(PLATFORM_SOURCES platform/platform_x11.cpp)
    set(PLATFORM_LIBS GLEW::GLEW X11::X11 GL)
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

target_include_directories(gl_spinning_triangle PRIVATE "${TRACY_DIR}/public")
target_link_libraries(gl_spinning_triangle PRIVATE ${PLATFORM_LIBS})
