ARCH := $(shell uname -m)

CFLAGS := -g3 -Wall
DEFINES := -DDEBUG
BUILD := debug

ifndef TRACY_NO_ISA_EXTENSIONS
ifeq ($(ARCH),x86_64)
CFLAGS += -msse4.1
endif
endif

include build.mk
