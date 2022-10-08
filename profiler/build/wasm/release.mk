CFLAGS := -Os
ifndef TRACY_NO_LTO
CFLAGS += -flto
endif
DEFINES := -DNDEBUG
BUILD := release
LIBS := -sASSERTIONS=0

include ../../../common/unix-release.mk
include build.mk
