CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=c++17
DEFINES += -DIMGUI_ENABLE_FREETYPE
INCLUDES := -I../../../imgui $(shell pkg-config --cflags glfw3 freetype2 capstone)
LIBS := $(shell pkg-config --libs glfw3 freetype2 capstone) -lpthread

PROJECT := Tracy
IMAGE := $(PROJECT)-$(BUILD)

FILTER := ../../../nfd/nfd_win.cpp
include ../../../common/src-from-vcxproj.mk

ifdef TRACY_NO_FILESELECTOR
	CXXFLAGS += -DTRACY_NO_FILESELECTOR
else
	UNAME := $(shell uname -s)
	ifeq ($(UNAME),Darwin)
		SRC3 += ../../../nfd/nfd_cocoa.m
		LIBS +=  -framework CoreFoundation -framework AppKit -framework UniformTypeIdentifiers
	else
		ifdef TRACY_GTK_FILESELECTOR
			SRC += ../../../nfd/nfd_gtk.cpp
			INCLUDES += $(shell pkg-config --cflags gtk+-3.0)
			LIBS += $(shell pkg-config --libs gtk+-3.0)
		else
			ifeq ($(shell uname -o),Haiku)
				SRC += ../../../nfd/nfd_haiku.cpp
				LIBS += -lbe -ltracker
			else
				SRC += ../../../nfd/nfd_portal.cpp
				INCLUDES += $(shell pkg-config --cflags dbus-1)
				LIBS += $(shell pkg-config --libs dbus-1)
			endif
		endif
	endif
endif

include ../../../common/unix.mk
