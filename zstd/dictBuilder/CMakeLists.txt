add_library(zstd.dictBuilder STATIC cover.c divsufsort.c fastcover.c zdict.c)

set_default_compile_options(zstd.dictBuilder)

target_link_libraries(zstd.dictBuilder PUBLIC zstd.common)
