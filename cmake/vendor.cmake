# Vendor Specific CMake
# The Tracy project keeps most vendor source locally

set (ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/../")

# Dependencies are taken from the system first and if not found, they are pulled with CPM and built from source

include(FindPkgConfig)
include(${CMAKE_CURRENT_LIST_DIR}/CPM.cmake)

option(DOWNLOAD_CAPSTONE "Force download capstone" ON)
option(DOWNLOAD_GLFW "Force download glfw" OFF)
option(DOWNLOAD_FREETYPE "Force download freetype" OFF)
option(DOWNLOAD_LIBCURL "Force download libcURL" OFF)
option(DOWNLOAD_PUGIXML "Force download pugixml" OFF)

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
        GIT_TAG 6.0.0-Alpha7
        OPTIONS
            "CAPSTONE_X86_ATT_DISABLE ON"
            "CAPSTONE_ALPHA_SUPPORT OFF"
            "CAPSTONE_ARC_SUPPORT OFF"
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
    target_link_libraries(TracyCapstone INTERFACE capstone_static)
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
        GIT_TAG VER-2-14-1
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
    GIT_TAG v1.92.6-docking
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
target_compile_definitions(TracyImGui PUBLIC "IMGUI_USE_WCHAR32")
#target_compile_definitions(TracyImGui PUBLIC "IMGUI_DISABLE_OBSOLETE_FUNCTIONS")

if (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND LEGACY)
    find_package(X11 REQUIRED)
    target_link_libraries(TracyImGui PUBLIC ${X11_LIBRARIES})
endif()

if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(TracyImGui PRIVATE "IMGUI_DISABLE_DEBUG_TOOLS" "IMGUI_DISABLE_DEMO_WINDOWS")
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
        GIT_TAG v1.3.0
        EXCLUDE_FROM_ALL TRUE
        OPTIONS
            "NFD_PORTAL ${NFD_PORTAL}"
    )
endif()

# PPQSort

CPMAddPackage(
    NAME PPQSort
    GITHUB_REPOSITORY GabTux/PPQSort
    VERSION 1.0.6
    PATCHES
        "${CMAKE_CURRENT_LIST_DIR}/ppqsort-nodebug.patch"
    EXCLUDE_FROM_ALL TRUE
)

# json

CPMAddPackage(
    NAME json
    GITHUB_REPOSITORY nlohmann/json
    GIT_TAG v3.12.0
    EXCLUDE_FROM_ALL TRUE
)

# md4c

CPMAddPackage(
    NAME md4c
    GITHUB_REPOSITORY mity/md4c
    GIT_TAG release-0.5.2
    EXCLUDE_FROM_ALL TRUE
)

if(NOT EMSCRIPTEN)

    # base64

    set(BUILD_SHARED_LIBS_SAVE ${BUILD_SHARED_LIBS})
    set(BUILD_SHARED_LIBS OFF)
    CPMAddPackage(
        NAME base64
        GITHUB_REPOSITORY aklomp/base64
        GIT_TAG v0.5.2
        OPTIONS
            "BASE64_BUILD_CLI OFF"
            "BASE64_WITH_OpenMP OFF"
        EXCLUDE_FROM_ALL TRUE
    )
    set(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_SAVE})

    # tidy

    CPMAddPackage(
        NAME tidy
        GITHUB_REPOSITORY htacg/tidy-html5
        GIT_TAG 5.8.0
        PATCHES
            "${CMAKE_CURRENT_LIST_DIR}/tidy-cmake.patch"
        EXCLUDE_FROM_ALL TRUE
    )

    # usearch

    CPMAddPackage(
        NAME usearch
        GITHUB_REPOSITORY unum-cloud/usearch
        GIT_TAG v2.23.0
        EXCLUDE_FROM_ALL TRUE
    )

    # pugixml

    pkg_check_modules(PUGIXML pugixml)
    if (PUGIXML_FOUND AND NOT DOWNLOAD_PUGIXML)
        add_library(TracyPugixml INTERFACE)
        target_include_directories(TracyPugixml INTERFACE ${PUGIXML_INCLUDE_DIRS})
        target_link_libraries(TracyPugixml INTERFACE ${PUGIXML_LINK_LIBRARIES})
    else()
        CPMAddPackage(
            NAME pugixml
            GITHUB_REPOSITORY zeux/pugixml
            GIT_TAG v1.15
            EXCLUDE_FROM_ALL TRUE
        )
        add_library(TracyPugixml INTERFACE)
        target_link_libraries(TracyPugixml INTERFACE pugixml)
    endif()

    # libcurl

    pkg_check_modules(LIBCURL libcurl>=7.87.0)
    if (LIBCURL_FOUND AND NOT DOWNLOAD_LIBCURL)
        add_library(TracyLibcurl INTERFACE)
        target_include_directories(TracyLibcurl INTERFACE ${LIBCURL_INCLUDE_DIRS})
        target_link_libraries(TracyLibcurl INTERFACE ${LIBCURL_LINK_LIBRARIES})
    else()
        CPMAddPackage(
            NAME libcurl
            GITHUB_REPOSITORY curl/curl
            GIT_TAG curl-8_18_0
            OPTIONS
                "BUILD_STATIC_LIBS ON"
                "BUILD_SHARED_LIBS OFF"
                "HTTP_ONLY ON"
                "CURL_ZSTD OFF"
                "CURL_USE_LIBPSL OFF"
            EXCLUDE_FROM_ALL TRUE
        )
        add_library(TracyLibcurl INTERFACE)
        target_link_libraries(TracyLibcurl INTERFACE libcurl_static)
        target_include_directories(TracyLibcurl INTERFACE ${libcurl_SOURCE_DIR}/include)
    endif()

endif()
