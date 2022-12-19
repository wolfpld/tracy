CFLAGS := -O3
ifndef TRACY_NO_LTO
CFLAGS += -flto
endif
DEFINES := -DNDEBUG
BUILD := release

include ../../../common/unix-release.mk

ifeq ($(LEGACY),1)
    include legacy.mk
else
    include build.mk
endif
