CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=gnu++17
DEFINES += -DTRACY_NO_STATISTICS
INCLUDES := $(shell pkg-config --cflags capstone)
LIBS := $(shell pkg-config --libs capstone) -lpthread
PROJECT := update
IMAGE := $(PROJECT)-$(BUILD)

FILTER :=
include ../../../common/src-from-vcxproj.mk

include ../../../common/unix.mk
