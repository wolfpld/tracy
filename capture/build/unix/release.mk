CFLAGS := -O3 -march=native
DEFINES := -DNDEBUG
BUILD := release

include ../../../common/unix-release.mk
include build.mk
