CC=gcc

INC=-I.
LIBS=-lgcrypt

CFLAGS= -g -Wall

%.o: %.c $(INC)
	$(CC) -c -o $@ $< $(CFLAGS) $(INC) $(LIBS)
all: crypt.o dcrypt.o
	$(CC) -o crypt crypt.o $(LIBS)
	$(CC) -o dcrypt dcrypt.o $(LIBS)
clean:
	rm *.o crypt dcrypt
