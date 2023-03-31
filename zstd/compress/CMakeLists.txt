add_library(
  zstd.compress STATIC
  zstd_compress_superblock.c
  zstdmt_compress.c
  zstd_double_fast.c
  zstd_fast.c
  zstd_compress_sequences.c
  zstd_ldm.c
  hist.c
  zstd_compress.c
  zstd_lazy.c
  zstd_compress_literals.c
  huf_compress.c
  zstd_opt.c
  fse_compress.c)

set_default_compile_options(zstd.compress)

target_link_libraries(zstd.compress PUBLIC zstd.common)
