OPTFLAGS := -g3 -fmerge-constants
CFLAGS := $(OPTFLAGS) -Wall -DTRACY_ENABLE
CXXFLAGS := $(CFLAGS) -std=gnu++11
DEFINES +=
INCLUDES := -I../public/tracy
LIBS := -lpthread -ldl
LDFLAGS := -rdynamic
IMAGE := tracy_test

SRC := \
    test.cpp \
    ../public/TracyClient.cpp

OBJ := $(SRC:%.cpp=%.o)

ifeq ($(shell uname -o),FreeBSD)
LIBS += -lexecinfo
endif

ifeq ($(shell uname),Linux)
DEFINES += -DTRACY_DEBUGINFOD
LIBS += -ldebuginfod
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
	$(CXX) $(CXXFLAGS) $(DEFINES) $(OBJ) $(LIBS) $(LDFLAGS) -o $@

ifneq "$(MAKECMDGOALS)" "clean"
-include $(SRC:.cpp=.d)
endif

clean:
	rm -f $(OBJ) $(SRC:.cpp=.d) $(IMAGE)

.PHONY: clean all
