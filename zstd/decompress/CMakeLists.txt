enable_language(ASM)

add_library(
  zstd.decompress STATIC
  zstd_ddict.c huf_decompress.c zstd_decompress.c zstd_decompress_block.c
  $<$<PLATFORM_ID:Darwin,Linux>:huf_decompress_amd64.S>)

set_default_compile_options(zstd.decompress)

target_link_libraries(zstd.decompress PUBLIC zstd.common)
