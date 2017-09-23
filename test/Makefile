CFLAGS := -g3 -Wall -fmerge-constants -D_GNU_SOURCE
CXXFLAGS := $(CFLAGS) -std=gnu++14
DEFINES +=
INCLUDES :=
LIBS := -lpthread
IMAGE := tracy_test

SRC := \
    test.cpp \
    ../client/TracyProfiler.cpp \
    ../common/tracy_lz4.cpp \
    ../common/TracySocket.cpp \
    ../common/TracySystem.cpp

OBJ := $(SRC:%.cpp=%.o)

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
