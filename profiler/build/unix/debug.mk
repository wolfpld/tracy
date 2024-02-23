ifeq ($(shell uname -o),Haiku)
CFLAGS := -gdwarf-3 -Wall
LDFLAGS := -gdwarf-3
else
CFLAGS := -g3 -Wall
LDFLAGS := -g3
endif
DEFINES := -DDEBUG
BUILD := debug

include ../../../common/unix-debug.mk

ifeq ($(LEGACY),1)
    include legacy.mk
else
    include build.mk
endif
