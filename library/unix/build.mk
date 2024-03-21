CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=c++11 -fpic
DEFINES += -DTRACY_ENABLE
INCLUDES :=
LIBS := -lpthread
PROJECT := libtracy
IMAGE := $(PROJECT)-$(BUILD).so
SHARED_LIBRARY := yes

SRC := ../../public/TracyClient.cpp

include ../../common/unix.mk
