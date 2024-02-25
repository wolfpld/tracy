CFLAGS := -g3 -Wall
LDFLAGS := -g3
DEFINES := -DDEBUG
BUILD := debug

include ../../../common/unix-debug.mk

ifeq ($(LEGACY),1)
    include legacy.mk
else
    include build.mk
endif
