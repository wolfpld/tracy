NVCC := nvcc
CFLAGS := -O2

.PHONY: all clean

all: repro

repro: repro.cu
	$(NVCC) $(CFLAGS) -o $@ $<

clean:
	rm -f repro
