CC=gcc

INC=-I.

CFLAGS= -g -Wall

%.o: %.c $(INC)
	$(CC) -c -o $@ $< $(CFLAGS) $(INC)
all: crypt.o dcrypt.o
	$(CC) -o crypt crypt.o
	$(CC) -o dcrypt dcrypt.o
clean:
	rm *.o crypt dcrypt
