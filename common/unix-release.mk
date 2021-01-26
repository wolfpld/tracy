ARCH := $(shell uname -m)

ifeq (0,$(shell $(CC) --version | grep clang && echo 1 || echo 0))
CFLAGS += -s
endif

ifeq ($(ARCH),aarch64)
CFLAGS += -mcpu=native
else
CFLAGS += -march=native
endif
