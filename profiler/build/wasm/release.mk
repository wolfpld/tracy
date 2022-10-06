CFLAGS := -Os
ifndef TRACY_NO_LTO
CFLAGS += -flto
endif
DEFINES := -DNDEBUG
BUILD := release

include ../../../common/unix-release.mk
include build.mk
