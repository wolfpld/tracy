CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=c++11 -fpic
DEFINES += -DTRACY_ENABLE
INCLUDES :=
LIBS := -lpthread -ldl
PROJECT := libtracy
IMAGE := $(PROJECT)-$(BUILD).so
SHARED_LIBRARY := yes

SRC := ../../TracyClient.cpp

include ../../common/unix.mk
