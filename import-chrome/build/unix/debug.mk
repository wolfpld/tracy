CFLAGS := -g3 -Wall
DEFINES := -DDEBUG
BUILD := debug

include ../../../common/unix-debug.mk
include build.mk
