# Common code needed by most Tracy Unix Makefiles.

# Ensure these are simply-substituted variables, without changing their values.
LIBS := $(LIBS)

ifndef NO_TBB
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
endif

OBJDIRBASE := obj/$(BUILD)
OBJDIR := $(OBJDIRBASE)/o/o/o

OBJ := $(addprefix $(OBJDIR)/,$(SRC:%.cpp=%.o))
OBJ2 := $(addprefix $(OBJDIR)/,$(SRC2:%.c=%.o))
OBJ3 := $(addprefix $(OBJDIR)/,$(SRC3:%.m=%.o))
OBJ4 := $(addprefix $(OBJDIR)/,$(SRC4:%.S=%.o))

all: $(IMAGE)

$(OBJDIR)/%.o: %.cpp
	$(CXX) -c $(INCLUDES) $(CXXFLAGS) $(DEFINES) $< -o $@

$(OBJDIR)/%.d : %.cpp
	@echo Resolving dependencies of $<
	@mkdir -p $(@D)
	@$(CXX) -MM $(INCLUDES) $(CXXFLAGS) $(DEFINES) $< > $@.$$$$; \
	sed 's,.*\.o[ :]*,$(OBJDIR)/$(<:.cpp=.o) $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

$(OBJDIR)/%.o: %.c
	$(CC) -c $(INCLUDES) $(CFLAGS) $(DEFINES) $< -o $@

$(OBJDIR)/%.d : %.c
	@echo Resolving dependencies of $<
	@mkdir -p $(@D)
	@$(CC) -MM $(INCLUDES) $(CFLAGS) $(DEFINES) $< > $@.$$$$; \
	sed 's,.*\.o[ :]*,$(OBJDIR)/$(<:.c=.o) $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

$(OBJDIR)/%.o: %.m
	$(CC) -c $(INCLUDES) $(CFLAGS) $(DEFINES) $< -o $@

$(OBJDIR)/%.d : %.m
	@echo Resolving dependencies of $<
	@mkdir -p $(@D)
	@$(CC) -MM $(INCLUDES) $(CFLAGS) $(DEFINES) $< > $@.$$$$; \
	sed 's,.*\.o[ :]*,$(OBJDIR)/$(<:.m=.o) $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

$(OBJDIR)/%.o: %.S
	$(CC) -c $(INCLUDES) $(CFLAGS) $(DEFINES) $< -o $@

$(OBJDIR)/%.d : %.S
	@echo Resolving dependencies of $<
	@mkdir -p $(@D)
	@$(CC) -MM $(INCLUDES) $(CFLAGS) $(DEFINES) $< > $@.$$$$; \
	sed 's,.*\.o[ :]*,$(OBJDIR)/$(<:.m=.o) $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

ifeq (yes,$(SHARED_LIBRARY))
$(IMAGE): $(OBJ) $(OBJ2) $(OBJ4)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(DEFINES) $(OBJ) $(OBJ2) $(OBJ4) $(LIBS) -shared -o $@
else
$(IMAGE): $(OBJ) $(OBJ2) $(OBJ3) $(OBJ4)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(DEFINES) $(OBJ) $(OBJ2) $(OBJ3) $(OBJ4) $(LIBS) -o $@
endif

ifneq "$(MAKECMDGOALS)" "clean"
-include $(addprefix $(OBJDIR)/,$(SRC:.cpp=.d)) $(addprefix $(OBJDIR)/,$(SRC2:.c=.d)) $(addprefix $(OBJDIR)/,$(SRC3:.m=.d)) $(addprefix $(OBJDIR)/,$(SRC4:.S=.d))
endif

clean:
	rm -rf $(OBJDIRBASE) $(IMAGE)*

.PHONY: clean all
