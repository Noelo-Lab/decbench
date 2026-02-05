# DecBench Example Project Makefile
# Generates executable and .o files with debug symbols and preprocessed .i files

CC = cc
# Base flags for reproducible decompilation benchmarking
CFLAGS = -g -fno-inline -fno-builtin -save-temps=obj -O2

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
