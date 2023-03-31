add_executable(capture src/capture.cpp)

set_default_compile_options(capture)

target_link_libraries(capture PRIVATE server getopt)
