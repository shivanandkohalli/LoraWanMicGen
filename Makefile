CC=gcc
CFLAGS = -g -Wall
EXEC = ./nwksintkeys

all:
	$(CC) $(CFLAGS) main.c -o $(EXEC) -lmbedcrypto

clean:
	-rm -f $(EXEC)