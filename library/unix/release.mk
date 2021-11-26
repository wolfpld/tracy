ARCH := $(shell uname -m)

CFLAGS := -O3 -s
DEFINES := -DNDEBUG
BUILD := release

ifndef TRACY_NO_ISA_EXTENSIONS
ifeq ($(ARCH),x86_64)
CFLAGS += -msse4.1
endif
endif

include build.mk
