CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=gnu++17
DEFINES += -DTRACY_NO_STATISTICS
INCLUDES := -I../../../capstone/include/capstone
LIBS += -lcapstone -lpthread
LDFLAGS := -L../../../capstone
PROJECT := tracy-edit
IMAGE := $(PROJECT)-$(BUILD)

FILTER :=
include ../../../common/src-from-vcxproj.mk

include ../../../common/unix.mk
