CFLAGS +=
CXXFLAGS := $(CFLAGS) -std=gnu++17 -fpic
DEFINES += -DTRACY_ENABLE
INCLUDES :=
LIBS := -lpthread -ldl
PROJECT := libtracy
IMAGE := $(PROJECT)-$(BUILD).so

SRC := ../../TracyClient.cpp

OBJDIRBASE := obj/$(BUILD)
OBJDIR := $(OBJDIRBASE)/o/o/o

OBJ := $(addprefix $(OBJDIR)/,$(SRC:%.cpp=%.o))

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

$(IMAGE): $(OBJ)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(OBJ) $(LIBS) -shared -o $@

ifneq "$(MAKECMDGOALS)" "clean"
-include $(addprefix $(OBJDIR)/,$(SRC:.cpp=.d))
endif

clean:
	rm -rf $(OBJDIRBASE) $(PROJECT)*.so

.PHONY: clean all
