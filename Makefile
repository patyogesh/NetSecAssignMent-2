CC=gcc

INC=-I.
LIBS=-lgcrypt

CFLAGS= -g

%.o: %.c $(INC)
	$(CC) -c -o $@ $< $(CFLAGS) $(INC) $(LIBS)
all: crypto.o crypt.o dcrypt.o
	$(CC) -o crypt crypt.o crypto.o $(LIBS)
	$(CC) -o dcrypt dcrypt.o crypto.o $(LIBS)
clean:
	rm *.o crypt dcrypt
