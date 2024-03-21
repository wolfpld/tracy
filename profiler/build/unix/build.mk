CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=c++17
DEFINES += -DIMGUI_ENABLE_FREETYPE
INCLUDES := -I../../../imgui $(shell pkg-config --cflags freetype2 capstone wayland-egl egl wayland-cursor xkbcommon)
LIBS := $(shell pkg-config --libs freetype2 capstone wayland-egl egl wayland-cursor xkbcommon) -lpthread

PROJECT := Tracy
IMAGE := $(PROJECT)-$(BUILD)

FILTER := ../../../nfd/nfd_win.cpp ../../src/BackendGlfw.cpp ../../src/imgui/imgui_impl_glfw.cpp
include ../../../common/src-from-vcxproj.mk

SRC += ../../src/BackendWayland.cpp
SRC2 += ../../src/wayland/xdg-shell.c ../../src/wayland/xdg-activation.c ../../src/wayland/xdg-decoration.c

ifdef TRACY_NO_FILESELECTOR
	CXXFLAGS += -DTRACY_NO_FILESELECTOR
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

include ../../../common/unix.mk
