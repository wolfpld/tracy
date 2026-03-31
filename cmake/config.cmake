# --------------------------------------------------
# Detect if Tracy is top-level
# --------------------------------------------------
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(TRACY_IS_TOP_LEVEL ON)
else()
    set(TRACY_IS_TOP_LEVEL OFF)
endif()

# --------------------------------------------------
# Options (safe defaults for subprojects)
# --------------------------------------------------
option(TRACY_AUTO_ENABLE_NATIVE "Enable native ISA extensions (-march/-mcpu=native)" ${TRACY_IS_TOP_LEVEL})
option(TRACY_AUTO_USE_LTO "Enable interprocedural optimization (LTO)" ${TRACY_IS_TOP_LEVEL})
option(TRACY_AUTO_USE_MOLD "Use mold linker if available" ${TRACY_IS_TOP_LEVEL})
option(TRACY_AUTO_USE_CCACHE "Enable ccache" ${TRACY_IS_TOP_LEVEL})


if (TRACY_AUTO_ENABLE_NATIVE AND NOT NO_ISA_EXTENSIONS)
    include(CheckCXXCompilerFlag)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        CHECK_CXX_COMPILER_FLAG("-mcpu=native" COMPILER_SUPPORTS_MCPU_NATIVE)
        if(COMPILER_SUPPORTS_MARCH_NATIVE)
            add_compile_options(-mcpu=native)
        endif()
    else()
        CHECK_CXX_COMPILER_FLAG("-march=native" COMPILER_SUPPORTS_MARCH_NATIVE)
        if(COMPILER_SUPPORTS_MARCH_NATIVE)
            add_compile_options(-march=native)
        endif()
    endif()
    if(WIN32)
        add_compile_options(/arch:AVX2)
    endif()
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT LEGACY)
    set(USE_WAYLAND ON)
else()
    set(USE_WAYLAND OFF)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "15")
          message(FATAL_ERROR "Apple Clang 15 or newer is required.")
        elseif(NOT CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "16")
          # AppleClang 15 has issues with to_chars in <chrono> if target is too old
          add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-mmacosx-version-min=13.3>)
        endif()
        add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fexperimental-library>)
    endif()
endif()

if(WIN32)
    add_definitions(-DNOMINMAX -DWIN32_LEAN_AND_MEAN -D_DISABLE_CONSTEXPR_MUTEX_CONSTRUCTOR)
    # /MP is MSVC-specific for multi-processor compilation
    if(MSVC)
        add_compile_options(/MP)
    endif()
endif()

if(EMSCRIPTEN)
    add_compile_options(-pthread -DIMGUI_IMPL_OPENGL_ES2)
endif()

if(TRACY_AUTO_USE_LTO AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT EMSCRIPTEN)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

if(TRACY_AUTO_USE_MOLD AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_program(MOLD_LINKER mold)
    if(MOLD_LINKER)
        set(CMAKE_LINKER_TYPE "MOLD")
    endif()
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-fno-eliminate-unused-debug-types)
    endif()
endif()

if(TRACY_AUTO_USE_CCACHE AND NOT CMAKE_C_COMPILER_LAUNCHER AND NOT CMAKE_CXX_COMPILER_LAUNCHER)
    find_program(CCACHE ccache)
    if(CCACHE)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
        set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache) 
    endif()
endif()

file(GENERATE OUTPUT .gitignore CONTENT "*")

set(CMAKE_COLOR_DIAGNOSTICS ON)
