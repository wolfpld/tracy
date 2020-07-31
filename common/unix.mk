# Common code needed by most Tracy Unix Makefiles.

# Ensure LIBS is a simply-substituted variable, without changing its value.
LIBS := $(LIBS)

# Tracy does not use TBB directly, but the implementation of parallel algorithms
# in some versions of libstdc++ depends on TBB. When it does, you must
# explicitly link against -ltbb.
#
# Some distributions have pgk-config files for TBB, others don't.
ifeq (0,$(shell pkg-config --libs tbb >/dev/null 2>&1; echo $$?))
	LIBS += $(shell pkg-config --libs tbb)
else ifeq (0,$(shell ld -ltbb -o /dev/null 2>/dev/null; echo $$?))
	LIBS += -ltbb
endif

