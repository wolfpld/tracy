add_library(
  zstd.common STATIC
  entropy_common.c
  fse_decompress.c
  debug.c
  xxhash.c
  pool.c
  threading.c
  zstd_common.c
  error_private.c)

set_default_compile_options(zstd.common)
