CFLAGS := -g3 -gsource-map -Wall
DEFINES := -DDEBUG
BUILD := debug
LIBS := -sDEMANGLE_SUPPORT=1

include ../../../common/unix-debug.mk
include build.mk
