CFLAGS := -Os
DEFINES := -DNDEBUG
BUILD := release
LIBS := -sASSERTIONS=0

include ../../../common/unix-release.mk
include build.mk
