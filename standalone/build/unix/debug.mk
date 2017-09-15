ARCH := $(shell uname -m)

CFLAGS := -g3 -Wall
DEFINES := -DDEBUG

ifeq ($(ARCH),x86_64)
CFLAGS += -msse4.1
endif

include build.mk
