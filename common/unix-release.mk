ifeq (0,$(shell $(CC) --version | grep clang && echo 1 || echo 0))
CFLAGS += -s
endif
