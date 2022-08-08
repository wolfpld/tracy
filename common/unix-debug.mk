ARCH := $(shell uname -m)

ifeq (1,$(shell $(CC) --version | grep clang > /dev/null && echo 1 || echo 0))
  ifeq (1,$(shell ld.mold --version > /dev/null 2> /dev/null && echo 1 || echo 0))
LDFLAGS := -fuse-ld=mold
  endif
endif

ifndef TRACY_NO_ISA_EXTENSIONS
ifneq (,$(filter $(ARCH),aarch64 arm64))
CFLAGS += -mcpu=native
else
CFLAGS += -march=native
endif
endif
