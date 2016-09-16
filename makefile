CC=gcc
CFLAGS=-O3
LIBS=-lsodium

all:
	$(CC) main.c $(CFLAGS) $(LIBS) -o secret

.PHONY: clean

clean:
	rm -f secret
