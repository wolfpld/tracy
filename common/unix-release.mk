ARCH := $(shell uname -m)

ifeq (0,$(shell $(CC) --version | grep clang && echo 1 || echo 0))
CFLAGS += -s
else
LDFLAGS := -s
endif

ifeq (1,$(shell ld.lld --version > /dev/null && echo 1 || echo 0))
LDFLAGS += -fuse-ld=lld
endif

ifneq (,$(filter $(ARCH),aarch64 arm64))
CFLAGS += -mcpu=native
else
CFLAGS += -march=native
endif
