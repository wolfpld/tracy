CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=gnu++17
DEFINES += -DTRACY_NO_STATISTICS
INCLUDES := $(shell pkg-config --cflags capstone)
LIBS += $(shell pkg-config --libs capstone) -lpthread
PROJECT := capture
IMAGE := $(PROJECT)-$(BUILD)

FILTER := ../../../getopt/getopt.c
include ../../../common/src-from-vcxproj.mk

include ../../../common/unix.mk
