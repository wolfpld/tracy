cmake_minimum_required(VERSION 3.10)

project(TracyCapture LANGUAGES CXX)

add_executable(TracyCapture)
add_executable(Tracy::TracyCapture ALIAS TracyCapture)

target_sources(TracyCapture
    PRIVATE
        src/capture.cpp
)
target_compile_definitions(TracyCapture
    PRIVATE
        TRACY_NO_STATISTICS
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
target_compile_features(TracyCapture
    PRIVATE
        cxx_std_17
)
target_link_libraries(TracyCapture
    PRIVATE
        TracyCommon
        TracyServer
        $<$<PLATFORM_ID:Windows>:TracyGetOpt>
)
set_target_properties(TracyCapture
    PROPERTIES
        CXX_STANDARD          17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS        OFF
        OUTPUT_NAME           "capture"
)

