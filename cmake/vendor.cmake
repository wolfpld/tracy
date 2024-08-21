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
        GIT_TAG 5.0.3
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
        GIT_TAG VER-2-13-2
        OPTIONS
            "FT_DISABLE_HARFBUZZ ON"
            "FT_WITH_HARFBUZZ OFF"
    )
    add_library(TracyFreetype INTERFACE)
    target_link_libraries(TracyFreetype INTERFACE freetype)
endif()

# zstd

set(ZSTD_DIR "${ROOT_DIR}/zstd")

set(ZSTD_SOURCES
    decompress/zstd_ddict.c
    decompress/zstd_decompress_block.c
    decompress/huf_decompress.c
    decompress/zstd_decompress.c
    common/zstd_common.c
    common/error_private.c
    common/xxhash.c
    common/entropy_common.c
    common/debug.c
    common/threading.c
    common/pool.c
    common/fse_decompress.c
    compress/zstd_ldm.c
    compress/zstd_compress_superblock.c
    compress/zstd_opt.c
    compress/zstd_compress_sequences.c
    compress/fse_compress.c
    compress/zstd_double_fast.c
    compress/zstd_compress.c
    compress/zstd_compress_literals.c
    compress/hist.c
    compress/zstdmt_compress.c
    compress/zstd_lazy.c
    compress/huf_compress.c
    compress/zstd_fast.c
    dictBuilder/zdict.c
    dictBuilder/cover.c
    dictBuilder/divsufsort.c
    dictBuilder/fastcover.c
)

list(TRANSFORM ZSTD_SOURCES PREPEND "${ZSTD_DIR}/")

set_property(SOURCE ${ZSTD_DIR}/decompress/huf_decompress_amd64.S APPEND PROPERTY COMPILE_OPTIONS "-x" "assembler-with-cpp")

add_library(TracyZstd STATIC ${ZSTD_SOURCES})
target_include_directories(TracyZstd PUBLIC ${ZSTD_DIR})
target_compile_definitions(TracyZstd PRIVATE ZSTD_DISABLE_ASM)


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
add_library(TracyGetOpt STATIC ${GETOPT_SOURCES} ${GETOPT_HEADERS})
target_include_directories(TracyGetOpt PUBLIC ${GETOPT_DIR})


# ImGui

set(IMGUI_DIR "${ROOT_DIR}/imgui")

set(IMGUI_SOURCES
    imgui_widgets.cpp
    imgui_draw.cpp
    imgui_demo.cpp
    imgui.cpp
    imgui_tables.cpp
    misc/freetype/imgui_freetype.cpp
)

list(TRANSFORM IMGUI_SOURCES PREPEND "${IMGUI_DIR}/")

add_definitions(-DIMGUI_ENABLE_FREETYPE)

add_library(TracyImGui STATIC ${IMGUI_SOURCES})
target_include_directories(TracyImGui PUBLIC ${IMGUI_DIR})
target_link_libraries(TracyImGui PUBLIC TracyFreetype)

# NFD

if (NOT NO_FILESELECTOR AND NOT EMSCRIPTEN)
    set(NFD_DIR "${ROOT_DIR}/nfd")

    if (WIN32)
        set(NFD_SOURCES "${NFD_DIR}/nfd_win.cpp")
    elseif (APPLE)
        set(NFD_SOURCES "${NFD_DIR}/nfd_cocoa.m")
    else()
        if (GTK_FILESELECTOR)
            set(NFD_SOURCES "${NFD_DIR}/nfd_gtk.cpp")
        else()
            set(NFD_SOURCES "${NFD_DIR}/nfd_portal.cpp")
        endif()
    endif()

    file(GLOB_RECURSE NFD_HEADERS CONFIGURE_DEPENDS RELATIVE ${NFD_DIR} "*.h")
    add_library(TracyNfd STATIC ${NFD_SOURCES} ${NFD_HEADERS})
    target_include_directories(TracyNfd PUBLIC ${NFD_DIR})

    if (APPLE)
        find_library(APPKIT_LIBRARY AppKit)
        find_library(UNIFORMTYPEIDENTIFIERS_LIBRARY UniformTypeIdentifiers)
        target_link_libraries(TracyNfd PUBLIC ${APPKIT_LIBRARY} ${UNIFORMTYPEIDENTIFIERS_LIBRARY})
    elseif (UNIX)
        if (GTK_FILESELECTOR)
            pkg_check_modules(GTK3 gtk+-3.0)
            if (NOT GTK3_FOUND)
                message(FATAL_ERROR "GTK3 not found. Please install it or set TRACY_GTK_FILESELECTOR to OFF.")
            endif()
            add_library(TracyGtk3 INTERFACE)
            target_include_directories(TracyGtk3 INTERFACE ${GTK3_INCLUDE_DIRS})
            target_link_libraries(TracyGtk3 INTERFACE ${GTK3_LINK_LIBRARIES})
            target_link_libraries(TracyNfd PUBLIC TracyGtk3)
        else()
            pkg_check_modules(DBUS dbus-1)
            if (NOT DBUS_FOUND)
                message(FATAL_ERROR "D-Bus not found. Please install it or set TRACY_GTK_FILESELECTOR to ON.")
            endif()
            add_library(TracyDbus INTERFACE)
            target_include_directories(TracyDbus INTERFACE ${DBUS_INCLUDE_DIRS})
            target_link_libraries(TracyDbus INTERFACE ${DBUS_LINK_LIBRARIES})
            target_link_libraries(TracyNfd PUBLIC TracyDbus)
        endif()
    endif()
endif()

# TBB
if (NO_PARALLEL_STL)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNO_PARALLEL_SORT")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_PARALLEL_SORT")
else()
    if (UNIX AND NOT APPLE AND NOT EMSCRIPTEN)
        # Tracy does not use TBB directly, but the implementation of parallel algorithms
        # in some versions of libstdc++ depends on TBB. When it does, you must
        # explicitly link against -ltbb.
        #
        # Some distributions have pgk-config files for TBB, others don't.

        pkg_check_modules(TBB tbb)
        if (TBB_FOUND)
            add_library(TracyTbb INTERFACE)
            target_include_directories(TracyTbb INTERFACE ${TBB_INCLUDE_DIRS})
            target_link_libraries(TracyTbb INTERFACE ${TBB_LINK_LIBRARIES})
        else()
            CPMAddPackage(
                NAME tbb
                GITHUB_REPOSITORY oneapi-src/oneTBB
                GIT_TAG v2021.12.0-rc2
                OPTIONS "TBB_TEST OFF"
            )
            add_library(TracyTbb INTERFACE)
            target_link_libraries(TracyTbb INTERFACE tbb)
        endif()
    endif()
endif()
