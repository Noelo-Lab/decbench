# DecBench Example Project Makefile
# Generates executable and .o files with debug symbols and preprocessed .i files

CC = cc
# Benchmark-critical flags are force-appended to whatever CFLAGS the
# environment provides: the DecBench pipeline injects the optimization level
# through env CFLAGS, and a user's own CFLAGS must not drop -g/-save-temps.
# (No -O here so the pipeline's chosen level always wins; plain `make`
# builds default to -O0.)
override CFLAGS += -g -fno-inline -fno-builtin -save-temps=obj

all: example example.o

# Build executable (for decompilation)
example: example.c
	$(CC) $(CFLAGS) -o example example.c

# Also build object file (for reference)
example.o: example.c
	$(CC) $(CFLAGS) -c -o example.o example.c

clean:
	rm -f example example.o example.i example.s example.bc

.PHONY: all clean
