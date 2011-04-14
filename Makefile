CC=gcc
CFLAGS=-c -Wall -g

all:
		$(CC) $(CFLAGS) inject_dso.c main.c
		$(CC) $(CFLAGS) test.c
#		$(CC) inject_dso.o main.o -o inject -ldl
		$(CC) inject_dso.o test.o -o test

clean:
	  rm -rf *.o
