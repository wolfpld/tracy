CFLAGS += 
CXXFLAGS := $(CFLAGS) -std=c++17
DEFINES += -DTRACY_FILESELECTOR -DTRACY_EXTENDED_FONT -DTRACY_ROOT_WINDOW -DIMGUI_IMPL_OPENGL_LOADER_GL3W
INCLUDES := $(shell pkg-config --cflags glfw3 freetype2) -I../../../imgui -I../../libs/gl3w
LIBS := $(shell pkg-config --libs glfw3 freetype2) -lpthread -ldl
PROJECT := Tracy
IMAGE := $(PROJECT)-$(BUILD)

FILTER := ../../../nfd/nfd_win.cpp

BASE := $(shell egrep 'ClCompile.*cpp"' ../win32/$(PROJECT).vcxproj | sed -e 's/.*\"\(.*\)\".*/\1/' | sed -e 's@\\@/@g')
BASE2 := $(shell egrep 'ClCompile.*c"' ../win32/$(PROJECT).vcxproj | sed -e 's/.*\"\(.*\)\".*/\1/' | sed -e 's@\\@/@g')

SRC := $(filter-out $(FILTER),$(BASE))
SRC2 := $(filter-out $(FILTER),$(BASE2))
SRC3 :=

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
	SRC3 += ../../../nfd/nfd_cocoa.m
	LIBS +=  -framework CoreFoundation -framework AppKit
else
	SRC2 += ../../../nfd/nfd_gtk.c
	INCLUDES += $(shell pkg-config --cflags gtk+-2.0)
	LIBS += $(shell pkg-config --libs gtk+-2.0) -lGL
endif

TBB := $(shell ld -ltbb -o /dev/null 2>/dev/null; echo $$?)
ifeq ($(TBB),0)
	LIBS += -ltbb
endif

OBJDIRBASE := obj/$(BUILD)
OBJDIR := $(OBJDIRBASE)/o/o/o

OBJ := $(addprefix $(OBJDIR)/,$(SRC:%.cpp=%.o))
OBJ2 := $(addprefix $(OBJDIR)/,$(SRC2:%.c=%.o))
OBJ3 := $(addprefix $(OBJDIR)/,$(SRC3:%.m=%.o))

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

$(IMAGE): $(OBJ) $(OBJ2) $(OBJ3)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(OBJ) $(OBJ2) $(OBJ3) $(LIBS) -o $@

ifneq "$(MAKECMDGOALS)" "clean"
-include $(addprefix $(OBJDIR)/,$(SRC:.cpp=.d)) $(addprefix $(OBJDIR)/,$(SRC2:.c=.d)) $(addprefix $(OBJDIR)/,$(SRC3:.m=.d))
endif

clean:
	rm -rf $(OBJDIRBASE) $(IMAGE)*

.PHONY: clean all
