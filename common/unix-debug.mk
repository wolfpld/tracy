ARCH := $(shell uname -m)

ifeq (1,$(shell $(CC) --version | grep clang > /dev/null && echo 1 || echo 0))
  ifeq (1,$(shell ld.mold --version > /dev/null && echo 1 || echo 0))
LDFLAGS := -fuse-ld=mold
  endif
endif

ifeq ($(ARCH),x86_64)
CFLAGS += -msse4.1
endif
