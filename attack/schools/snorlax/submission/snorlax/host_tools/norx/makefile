# Compiler & Compiler flags
CC = gcc
CFLAGS = -Wall -fPIC -shared

# source files from directory
NORX_SRC = $(wildcard src/*.c)

all:
	$(CC) $(CFLAGS) $(NORX_SRC) -g -o norx.so
