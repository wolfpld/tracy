CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=gnu++17
DEFINES += -DTRACY_NO_STATISTICS
INCLUDES :=
LIBS := -lpthread
PROJECT := capture
IMAGE := $(PROJECT)-$(BUILD)

FILTER :=

BASE := $(shell egrep 'ClCompile.*cpp"' ../win32/$(PROJECT).vcxproj | sed -e 's/.*\"\(.*\)\".*/\1/' | sed -e 's@\\@/@g')
BASE2 := $(shell egrep 'ClCompile.*c"' ../win32/$(PROJECT).vcxproj | sed -e 's/.*\"\(.*\)\".*/\1/' | sed -e 's@\\@/@g')

SRC := $(filter-out $(FILTER),$(BASE))
SRC2 := $(filter-out $(FILTER),$(BASE2))

TBB := $(shell ld -ltbb -o /dev/null 2>/dev/null; echo $$?)
ifeq ($(TBB),0)
	LIBS += -ltbb
endif

OBJDIRBASE := obj/$(BUILD)
OBJDIR := $(OBJDIRBASE)/o/o/o

OBJ := $(addprefix $(OBJDIR)/,$(SRC:%.cpp=%.o))
OBJ2 := $(addprefix $(OBJDIR)/,$(SRC2:%.c=%.o))

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

$(IMAGE): $(OBJ) $(OBJ2)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(OBJ) $(OBJ2) $(LIBS) -o $@

ifneq "$(MAKECMDGOALS)" "clean"
-include $(addprefix $(OBJDIR)/,$(SRC:.cpp=.d)) $(addprefix $(OBJDIR)/,$(SRC2:.c=.d))
endif

clean:
	rm -rf $(OBJDIRBASE) $(IMAGE)*

.PHONY: clean all
