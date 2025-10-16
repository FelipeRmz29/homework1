# Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
TARGET = procman
SRCS = procman.c
HDRS = procman.h

.PHONY: all clean test valgrind strace

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

clean:
	rm -f $(TARGET) *.o

test: all
	@echo "--- Running Test Suite ---"
	@./test_scripts/test1.sh
	@./test_scripts/test2.sh
	@./test_scripts/test3.sh
	@echo "--- Test Suite Complete ---"

valgrind: all
	@echo "--- Running Valgrind Check ---"
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET)

strace: all
	@echo "--- Running Strace Check (Follows child processes -f) ---"
	strace -f -e trace=fork,execve,wait4,kill ./$(TARGET)

