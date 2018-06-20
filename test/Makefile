OPTFLAGS := -g3 -fmerge-constants
CFLAGS := $(OPTFLAGS) -Wall -DTRACY_ENABLE -rdynamic
CXXFLAGS := $(CFLAGS) -std=gnu++17
DEFINES +=
INCLUDES :=
LIBS := -lpthread -ldl
IMAGE := tracy_test

SRC := \
    test.cpp \
    ../TracyClient.cpp

OBJ := $(SRC:%.cpp=%.o)

ifeq ($(shell uname -o),Cygwin)
LIBS += -ldbghelp
endif

all: $(IMAGE)

%.o: %.cpp
	$(CXX) -c $(INCLUDES) $(CXXFLAGS) $(DEFINES) $< -o $@

%.d : %.cpp
	@echo Resolving dependencies of $<
	@mkdir -p $(@D)
	@$(CXX) -MM $(INCLUDES) $(CXXFLAGS) $(DEFINES) $< > $@.$$$$; \
	sed 's,.*\.o[ :]*,$(<:.cpp=.o) $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

$(IMAGE): $(OBJ)
	$(CXX) $(CXXFLAGS) $(DEFINES) $(OBJ) $(LIBS) -o $@

ifneq "$(MAKECMDGOALS)" "clean"
-include $(SRC:.cpp=.d)
endif

clean:
	rm -f $(OBJ) $(SRC:.cpp=.d) $(IMAGE)

.PHONY: clean all
