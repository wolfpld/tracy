OPTFLAGS := -g3 -fmerge-constants
TRACYFLAGS :=
CFLAGS := $(OPTFLAGS) -Wall -DTRACY_ENABLE $(TRACYFLAGS) -rdynamic
CXXFLAGS := $(CFLAGS) -std=gnu++11
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
ifeq ($(shell uname -o),FreeBSD)
LIBS += -lexecinfo
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
