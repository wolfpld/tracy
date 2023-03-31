add_executable(csvexport src/csvexport.cpp)

set_default_compile_options(csvexport)

target_link_libraries(csvexport PRIVATE server getopt)
