# CMakeLists.txt — WebGPU spinning triangle demo
#
#   macOS:
#     clang++ -std=c++17 -ObjC++ spinning_triangle.cpp platform/platform_macos.mm \
#         -I/path/to/wgpu/include -L/path/to/wgpu/lib -lwgpu_native \
#         -Wl,-rpath,@executable_path \
#         -framework Cocoa -framework Metal -framework QuartzCore \
#         -framework Foundation -framework IOKit -framework IOSurface \
#         -o spinning_triangle
#
#   Windows (MSVC):
#     cl /std:c++17 spinning_triangle.cpp platform/platform_windows.cpp \
#         /I\path\to\wgpu\include \path\to\wgpu\lib\wgpu_native.lib \
#         user32.lib gdi32.lib /Fe:spinning_triangle.exe
#
#   Linux / Wayland:
#     g++ -std=c++17 spinning_triangle.cpp platform/platform_wayland.cpp \
#         xdg-shell-protocol.c \
#         -I/path/to/wgpu/include -L/path/to/wgpu/lib -lwgpu_native \
#         -lwayland-client -o spinning_triangle

cmake_minimum_required(VERSION 3.16)
project(spinning_triangle LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# WebGPU backend — set WGPU_PATH to your wgpu-native or Dawn installation.
# The library name differs between backends:
#   wgpu-native  →  wgpu_native
#   Dawn         →  webgpu_dawn
# ---------------------------------------------------------------------------
set(WGPU_PATH "" CACHE PATH "Root of the WebGPU native installation (contains include/ and lib/)")
set(WGPU_LIB  "webgpu_dawn" CACHE STRING "WebGPU library name (wgpu_native or webgpu_dawn)")

if(NOT WGPU_PATH)
    message(FATAL_ERROR "Set WGPU_PATH to the root of your WebGPU native installation.")
endif()

# ---------------------------------------------------------------------------
# Tracy root — defaults to two directories above this CMakeLists.txt.
# ---------------------------------------------------------------------------
set(TRACY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
option(TRACY_ENABLE "Enable Tracy profiling" ON)

# ---------------------------------------------------------------------------
# macOS quarantine — pre-built WebGPU binaries downloaded from the internet
# carry a com.apple.quarantine extended attribute that prevents dyld from
# loading them ("damaged or incomplete" / Gatekeeper block).  Strip it once
# at configure time so the linker and the runtime loader can both access the
# library directory without further user intervention.
# ---------------------------------------------------------------------------
if(APPLE)
    execute_process(
        COMMAND xattr -dr com.apple.quarantine "${WGPU_PATH}/lib"
    )
endif()

# ---------------------------------------------------------------------------
# Platform-specific source and link settings
# ---------------------------------------------------------------------------
if(APPLE)
    set(PLATFORM_SOURCES platform/platform_macos.mm)
    set(PLATFORM_LIBS
        "-framework Cocoa"
        "-framework Metal"
        "-framework QuartzCore"
        "-framework Foundation"
        "-framework IOKit"
        "-framework IOSurface"
    )
    set_source_files_properties(platform/platform_macos.mm
        PROPERTIES COMPILE_FLAGS "-ObjC++"
    )
elseif(WIN32)
    set(PLATFORM_SOURCES platform/platform_windows.cpp)
    set(PLATFORM_LIBS user32 gdi32)
else()
    # Linux / Wayland — also needs the generated xdg-shell protocol glue.
    set(PLATFORM_SOURCES
        platform/platform_wayland.cpp
        platform/xdg-shell-protocol.c
    )
    set(PLATFORM_LIBS wayland-client)
endif()

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
add_executable(spinning_triangle
    spinning_triangle.cpp
    "${TRACY_DIR}/public/TracyClient.cpp"
    ${PLATFORM_SOURCES}
)

# Treat TracyClient.cpp as third-party code — suppress all warnings so that
# upstream changes don't pollute our build output.
if(MSVC)
    set_source_files_properties("${TRACY_DIR}/public/TracyClient.cpp"
        PROPERTIES COMPILE_FLAGS "/w"
    )
else()
    set_source_files_properties("${TRACY_DIR}/public/TracyClient.cpp"
        PROPERTIES COMPILE_FLAGS "-w"
    )
endif()

target_compile_features(spinning_triangle PRIVATE cxx_std_17)

if(TRACY_ENABLE)
    target_compile_definitions(spinning_triangle PRIVATE TRACY_ENABLE)
endif()

target_include_directories(spinning_triangle PRIVATE
    "${WGPU_PATH}/include"
    "${TRACY_DIR}/public"
)

target_link_directories(spinning_triangle PRIVATE "${WGPU_PATH}/lib")

target_link_libraries(spinning_triangle PRIVATE
    ${WGPU_LIB}
    ${PLATFORM_LIBS}
)

# Embed the rpath so the binary finds the WebGPU dylib/so next to itself.
if(APPLE)
    set_target_properties(spinning_triangle PROPERTIES
        BUILD_RPATH "${WGPU_PATH}/lib"
        INSTALL_RPATH "@executable_path"
    )
elseif(UNIX)
    set_target_properties(spinning_triangle PROPERTIES
        BUILD_RPATH "${WGPU_PATH}/lib"
        INSTALL_RPATH "$ORIGIN"
    )
endif()
