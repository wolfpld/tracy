CFLAGS := -O3 -flto
DEFINES := -DNDEBUG
BUILD := release

include ../../../common/unix-release.mk
include build.mk
