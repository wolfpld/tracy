#include <limits.h>
#if __WORDSIZE == 64
#  define BACKTRACE_ELF_SIZE 64
#else
#  define BACKTRACE_ELF_SIZE 32
#endif

#define HAVE_DLFCN_H
#define HAVE_FCNTL
#define HAVE_INTTYPES_H
#define HAVE_LSTAT
#define HAVE_READLINK
#define HAVE_DL_ITERATE_PHDR
