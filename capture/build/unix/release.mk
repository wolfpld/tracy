CFLAGS := -O3
DEFINES := -DNDEBUG
BUILD := release

include ../../../common/unix-release.mk
include build.mk
