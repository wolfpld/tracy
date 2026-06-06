TRACY_PUBLIC := ../../public
CXX          := g++

TRACY_SRCS   := $(TRACY_PUBLIC)/TracyClient.cpp
INCLUDES     := -I$(TRACY_PUBLIC) -I$(TRACY_PUBLIC)/tracy
LIBS         := -lpthread -ldl

CXXFLAGS     := -std=c++17 -O2 -DTRACY_ENABLE

.PHONY: all clean

all: seq

seq: seq.cpp tracy_client.o
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< tracy_client.o $(LIBS)

tracy_client.o: $(TRACY_SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

clean:
	rm -f seq tracy_client.o
