project(TracyGetOpt LANGUAGES C)

add_library(TracyGetOpt STATIC)
add_library(Tracy::TracyGetOpt ALIAS TracyGetOpt)

target_sources(TracyGetOpt
    PRIVATE
        getopt.c
        getopt.h
)
target_include_directories(TracyGetOpt
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
)
target_compile_definitions(TracyGetOpt
    PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:
            /permissive-
            /W3
        >
)
