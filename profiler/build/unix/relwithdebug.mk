CFLAGS := -O3 -g
ifndef TRACY_NO_LTO
CFLAGS += -flto
endif
DEFINES := -DNDEBUG
BUILD := release-with-debug

include ../../../common/unix-debug.mk

ifeq ($(LEGACY),1)
    include legacy.mk
else
    include build.mk
endif
