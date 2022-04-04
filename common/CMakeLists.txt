cmake_minimum_required(VERSION 3.10)

project(TracyCommon LANGUAGES C CXX)

add_library(TracyCommon STATIC)
add_library(Tracy::TracyCommon ALIAS TracyCommon)

target_sources(TracyCommon
    PRIVATE
        tracy_lz4.cpp
        tracy_lz4.hpp
        tracy_lz4hc.cpp
        tracy_lz4hc.hpp
        TracyAlign.hpp
        TracyAlloc.hpp
        TracyApi.h
        TracyColor.hpp
        TracyForceInline.hpp
        TracyMutex.hpp
        TracyProtocol.hpp
        TracyQueue.hpp
        TracySocket.cpp
        TracySocket.hpp
        TracyStackFrames.cpp
        TracyStackFrames.hpp
        TracySystem.cpp
        TracySystem.hpp
        TracyUwp.hpp
        TracyYield.hpp
)
target_include_directories(TracyCommon
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
)
target_compile_definitions(TracyCommon
    PRIVATE
        $<$<PLATFORM_ID:Windows>:
            _CRT_SECURE_NO_DEPRECATE
            _CRT_NONSTDC_NO_DEPRECATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            _USE_MATH_DEFINES
        >
        $<$<CXX_COMPILER_ID:MSVC>:
            /permissive-
            /W3
        >
)
target_compile_features(TracyCommon
    PUBLIC
        cxx_std_17
)
target_link_libraries(TracyCommon
    PUBLIC
        $<$<PLATFORM_ID:Windows>:
            ws2_32.lib
        >
        $<$<PLATFORM_ID:Linux>:
            PkgConfig::TBB
        >
)
set_target_properties(TracyCommon
    PROPERTIES
        CXX_STANDARD          17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS        OFF
)

