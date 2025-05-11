# Vendor Specific CMake
# The Tracy project keeps most vendor source locally

set (ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/../")

# Dependencies are taken from the system first and if not found, they are pulled with CPM and built from source

include(FindPkgConfig)
include(${CMAKE_CURRENT_LIST_DIR}/CPM.cmake)

option(DOWNLOAD_CAPSTONE "Force download capstone" ON)
option(DOWNLOAD_GLFW "Force download glfw" OFF)
option(DOWNLOAD_FREETYPE "Force download freetype" OFF)

# capstone

pkg_check_modules(CAPSTONE capstone)
if(CAPSTONE_FOUND AND NOT DOWNLOAD_CAPSTONE)
    message(STATUS "Capstone found: ${CAPSTONE}")
    add_library(TracyCapstone INTERFACE)
    target_include_directories(TracyCapstone INTERFACE ${CAPSTONE_INCLUDE_DIRS})
    target_link_libraries(TracyCapstone INTERFACE ${CAPSTONE_LINK_LIBRARIES})
else()
    CPMAddPackage(
        NAME capstone
        GITHUB_REPOSITORY capstone-engine/capstone
        GIT_TAG 6.0.0-Alpha1
        OPTIONS
            "CAPSTONE_X86_ATT_DISABLE ON"
            "CAPSTONE_ALPHA_SUPPORT OFF"
            "CAPSTONE_HPPA_SUPPORT OFF"
            "CAPSTONE_LOONGARCH_SUPPORT OFF"
            "CAPSTONE_M680X_SUPPORT OFF"
            "CAPSTONE_M68K_SUPPORT OFF"
            "CAPSTONE_MIPS_SUPPORT OFF"
            "CAPSTONE_MOS65XX_SUPPORT OFF"
            "CAPSTONE_PPC_SUPPORT OFF"
            "CAPSTONE_SPARC_SUPPORT OFF"
            "CAPSTONE_SYSTEMZ_SUPPORT OFF"
            "CAPSTONE_XCORE_SUPPORT OFF"
            "CAPSTONE_TRICORE_SUPPORT OFF"
            "CAPSTONE_TMS320C64X_SUPPORT OFF"
            "CAPSTONE_M680X_SUPPORT OFF"
            "CAPSTONE_EVM_SUPPORT OFF"
            "CAPSTONE_WASM_SUPPORT OFF"
            "CAPSTONE_BPF_SUPPORT OFF"
            "CAPSTONE_RISCV_SUPPORT OFF"
            "CAPSTONE_SH_SUPPORT OFF"
            "CAPSTONE_XTENSA_SUPPORT OFF"
            "CAPSTONE_BUILD_MACOS_THIN ON"
        EXCLUDE_FROM_ALL TRUE
    )
    add_library(TracyCapstone INTERFACE)
    target_include_directories(TracyCapstone INTERFACE ${capstone_SOURCE_DIR}/include/capstone)
    target_link_libraries(TracyCapstone INTERFACE capstone)
endif()

# GLFW

if(NOT USE_WAYLAND AND NOT EMSCRIPTEN)
    pkg_check_modules(GLFW glfw3)
    if (GLFW_FOUND AND NOT DOWNLOAD_GLFW)
        add_library(TracyGlfw3 INTERFACE)
        target_include_directories(TracyGlfw3 INTERFACE ${GLFW_INCLUDE_DIRS})
        target_link_libraries(TracyGlfw3 INTERFACE ${GLFW_LINK_LIBRARIES})
    else()
        CPMAddPackage(
            NAME glfw
            GITHUB_REPOSITORY glfw/glfw
            GIT_TAG 3.4
            OPTIONS
                "GLFW_BUILD_EXAMPLES OFF"
                "GLFW_BUILD_TESTS OFF"
                "GLFW_BUILD_DOCS OFF"
                "GLFW_INSTALL OFF"
            EXCLUDE_FROM_ALL TRUE
        )
        add_library(TracyGlfw3 INTERFACE)
        target_link_libraries(TracyGlfw3 INTERFACE glfw)
    endif()
endif()

# freetype

pkg_check_modules(FREETYPE freetype2)
if (FREETYPE_FOUND AND NOT DOWNLOAD_FREETYPE)
    add_library(TracyFreetype INTERFACE)
    target_include_directories(TracyFreetype INTERFACE ${FREETYPE_INCLUDE_DIRS})
    target_link_libraries(TracyFreetype INTERFACE ${FREETYPE_LINK_LIBRARIES})
else()
    CPMAddPackage(
        NAME freetype
        GITHUB_REPOSITORY freetype/freetype
        GIT_TAG VER-2-13-3
        OPTIONS
            "FT_DISABLE_HARFBUZZ ON"
            "FT_WITH_HARFBUZZ OFF"
        EXCLUDE_FROM_ALL TRUE
    )
    add_library(TracyFreetype INTERFACE)
    target_link_libraries(TracyFreetype INTERFACE freetype)
endif()

# Zstd

CPMAddPackage(
    NAME zstd
    GITHUB_REPOSITORY facebook/zstd
    GIT_TAG v1.5.7
    OPTIONS
        "ZSTD_BUILD_SHARED OFF"
    EXCLUDE_FROM_ALL TRUE
    SOURCE_SUBDIR build/cmake
)

# Diff Template Library

set(DTL_DIR "${ROOT_DIR}/dtl")
file(GLOB_RECURSE DTL_HEADERS CONFIGURE_DEPENDS RELATIVE ${DTL_DIR} "*.hpp")
add_library(TracyDtl INTERFACE)
target_sources(TracyDtl INTERFACE ${DTL_HEADERS})
target_include_directories(TracyDtl INTERFACE ${DTL_DIR})

# Get Opt

set(GETOPT_DIR "${ROOT_DIR}/getopt")
set(GETOPT_SOURCES ${GETOPT_DIR}/getopt.c)
set(GETOPT_HEADERS ${GETOPT_DIR}/getopt.h)
add_library(TracyGetOpt STATIC EXCLUDE_FROM_ALL ${GETOPT_SOURCES} ${GETOPT_HEADERS})
target_include_directories(TracyGetOpt PUBLIC ${GETOPT_DIR})

# ImGui

CPMAddPackage(
    NAME ImGui
    GITHUB_REPOSITORY ocornut/imgui
    GIT_TAG v1.91.9b-docking
    DOWNLOAD_ONLY TRUE
    PATCHES
        "${CMAKE_CURRENT_LIST_DIR}/imgui-emscripten.patch"
        "${CMAKE_CURRENT_LIST_DIR}/imgui-loader.patch"
)

set(IMGUI_SOURCES
    imgui_widgets.cpp
    imgui_draw.cpp
    imgui_demo.cpp
    imgui.cpp
    imgui_tables.cpp
    misc/freetype/imgui_freetype.cpp
    backends/imgui_impl_opengl3.cpp
)

list(TRANSFORM IMGUI_SOURCES PREPEND "${ImGui_SOURCE_DIR}/")

add_library(TracyImGui STATIC EXCLUDE_FROM_ALL ${IMGUI_SOURCES})
target_include_directories(TracyImGui PUBLIC ${ImGui_SOURCE_DIR})
target_link_libraries(TracyImGui PUBLIC TracyFreetype)
target_compile_definitions(TracyImGui PRIVATE "IMGUI_ENABLE_FREETYPE")

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(TracyImGui PRIVATE "IMGUI_DISABLE_DEBUG_TOOLS")
endif()

# NFD

if(NOT NO_FILESELECTOR AND NOT EMSCRIPTEN)
    if(GTK_FILESELECTOR)
        set(NFD_PORTAL OFF)
    else()
        set(NFD_PORTAL ON)
    endif()

    CPMAddPackage(
        NAME nfd
        GITHUB_REPOSITORY btzy/nativefiledialog-extended
        GIT_TAG v1.2.1
        EXCLUDE_FROM_ALL TRUE
        OPTIONS
            "NFD_PORTAL ${NFD_PORTAL}"
    )
endif()

# PPQSort

CPMAddPackage(
    NAME PPQSort
    GITHUB_REPOSITORY GabTux/PPQSort
    VERSION 1.0.5
    EXCLUDE_FROM_ALL TRUE
)
