ARCH := $(shell uname -m)

ifeq (1,$(shell ld.lld --version > /dev/null && echo 1 || echo 0))
LDFLAGS += -fuse-ld=lld
endif

ifeq ($(ARCH),x86_64)
CFLAGS += -msse4.1
endif
