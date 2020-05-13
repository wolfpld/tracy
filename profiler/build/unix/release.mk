ARCH := $(shell uname -m)

CFLAGS := -O3 -s -march=native
DEFINES := -DNDEBUG
BUILD := release

include build.mk
