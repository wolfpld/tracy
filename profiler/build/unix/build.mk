CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=c++17
DEFINES += -DIMGUI_IMPL_OPENGL_LOADER_GL3W
INCLUDES := $(shell pkg-config --cflags glfw3 freetype2 capstone) -I../../../imgui -I../../libs/gl3w
LIBS := $(shell pkg-config --libs glfw3 freetype2 capstone) -lpthread -ldl

DISPLAY_SERVER := X11

ifdef TRACY_USE_WAYLAND
	DISPLAY_SERVER := WAYLAND
	LIBS += $(shell pkg-config --libs wayland-client)
endif

CXXFLAGS += -D"DISPLAY_SERVER_$(DISPLAY_SERVER)"

PROJECT := Tracy
IMAGE := $(PROJECT)-$(BUILD)

FILTER := ../../../nfd/nfd_win.cpp
include ../../../common/src-from-vcxproj.mk

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
	SRC3 += ../../../nfd/nfd_cocoa.m
	LIBS +=  -framework CoreFoundation -framework AppKit
else
	SRC2 += ../../../nfd/nfd_gtk.c
	INCLUDES += $(shell pkg-config --cflags gtk+-3.0)
	LIBS += $(shell pkg-config --libs gtk+-3.0) -lGL
endif

include ../../../common/unix.mk
