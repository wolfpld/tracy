add_executable(update src/update.cpp)

set_default_compile_options(update)

target_link_libraries(update PRIVATE server getopt)
