add_subdirectory(common)

add_subdirectory(compress)

add_subdirectory(decompress)

add_subdirectory(dictBuilder)

add_library(zstd INTERFACE)

target_link_libraries(zstd INTERFACE zstd.compress zstd.decompress
                                     zstd.dictBuilder)
