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
set(WGPU_LIB  "" CACHE STRING "WebGPU library name (wgpu_native or webgpu_dawn); auto-detected if empty")

if(NOT WGPU_PATH)
    message(FATAL_ERROR "Set WGPU_PATH to the root of your WebGPU native installation.")
endif()

# When WGPU_PATH changes, discard any previously auto-detected WGPU_LIB so
# detection re-runs against the new path.
if(NOT "${WGPU_PATH}" STREQUAL "${_WGPU_PATH_LAST}" AND _WGPU_LIB_AUTO)
    unset(WGPU_LIB CACHE)
    set(WGPU_LIB "" CACHE STRING "WebGPU library name (wgpu_native or webgpu_dawn); auto-detected if empty")
endif()
set(_WGPU_PATH_LAST "${WGPU_PATH}" CACHE INTERNAL "")

if(NOT WGPU_LIB)
    # Always unset the find_library results so they re-probe the current WGPU_PATH.
    unset(_WGPU_NATIVE_LIB CACHE)
    unset(_WEBGPU_DAWN_LIB CACHE)
    find_library(_WGPU_NATIVE_LIB NAMES wgpu_native wgpu_native.dll PATHS "${WGPU_PATH}/lib" NO_DEFAULT_PATH)
    find_library(_WEBGPU_DAWN_LIB NAMES webgpu_dawn                 PATHS "${WGPU_PATH}/lib" NO_DEFAULT_PATH)
    if(_WGPU_NATIVE_LIB)
        set(WGPU_LIB "wgpu_native" CACHE STRING "WebGPU library name (wgpu_native or webgpu_dawn); auto-detected if empty" FORCE)
    elseif(_WEBGPU_DAWN_LIB)
        set(WGPU_LIB "webgpu_dawn" CACHE STRING "WebGPU library name (wgpu_native or webgpu_dawn); auto-detected if empty" FORCE)
    else()
        message(FATAL_ERROR "Could not detect a WebGPU library in ${WGPU_PATH}/lib. Set WGPU_LIB explicitly (wgpu_native or webgpu_dawn).")
    endif()
    set(_WGPU_LIB_AUTO TRUE CACHE INTERNAL "")
    message(STATUS "WebGPU library auto-detected: ${WGPU_LIB}")
else()
    set(_WGPU_LIB_AUTO FALSE CACHE INTERNAL "")
endif()

# ---------------------------------------------------------------------------
# Tracy root — defaults to two directories above this CMakeLists.txt.
# ---------------------------------------------------------------------------
set(TRACY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
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
set(PLATFORM_GENERATED_INCLUDES "")

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
    # Linux / Wayland — generate xdg-shell protocol glue via wayland-scanner.
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(WAYLAND_PROTOCOLS REQUIRED wayland-protocols)
    pkg_get_variable(WAYLAND_PROTOCOLS_DIR wayland-protocols pkgdatadir)
    find_program(WAYLAND_SCANNER wayland-scanner REQUIRED)

    set(XDG_SHELL_XML "${WAYLAND_PROTOCOLS_DIR}/stable/xdg-shell/xdg-shell.xml")
    set(XDG_SHELL_H   "${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-client-protocol.h")
    set(XDG_SHELL_C   "${CMAKE_CURRENT_BINARY_DIR}/xdg-shell-protocol.c")

    add_custom_command(
        OUTPUT  "${XDG_SHELL_H}"
        COMMAND "${WAYLAND_SCANNER}" client-header "${XDG_SHELL_XML}" "${XDG_SHELL_H}"
        DEPENDS "${XDG_SHELL_XML}"
        COMMENT "Generating xdg-shell-client-protocol.h"
        VERBATIM
    )
    add_custom_command(
        OUTPUT  "${XDG_SHELL_C}"
        COMMAND "${WAYLAND_SCANNER}" private-code  "${XDG_SHELL_XML}" "${XDG_SHELL_C}"
        DEPENDS "${XDG_SHELL_XML}"
        COMMENT "Generating xdg-shell-protocol.c"
        VERBATIM
    )

    set(PLATFORM_SOURCES
        platform/platform_wayland.cpp
        "${XDG_SHELL_C}"
        "${XDG_SHELL_H}"
    )
    set(PLATFORM_LIBS wayland-client)
    set(PLATFORM_GENERATED_INCLUDES "${CMAKE_CURRENT_BINARY_DIR}")
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
    ${PLATFORM_GENERATED_INCLUDES}
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
