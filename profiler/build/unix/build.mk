CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=c++17
DEFINES += -DIMGUI_ENABLE_FREETYPE
INCLUDES := $(shell pkg-config --cflags freetype2 capstone wayland-egl egl wayland-cursor xkbcommon) -I../../../imgui
LIBS := $(shell pkg-config --libs freetype2 capstone wayland-egl egl wayland-cursor xkbcommon) -lpthread -ldl

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
		SRC += ../../../nfd/nfd_portal.cpp
		INCLUDES += $(shell pkg-config --cflags dbus-1)
		LIBS += $(shell pkg-config --libs dbus-1)
	endif
endif

include ../../../common/unix.mk
