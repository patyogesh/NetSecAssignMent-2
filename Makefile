CC=gcc

INC=-I.
LIBS=-lgcrypt

CFLAGS= -g

%.o: %.c $(INC)
	$(CC) -c -o $@ $< $(CFLAGS) $(INC) $(LIBS)
all: crypto.o gatorcrypt.o gatordec.o
	$(CC) -o gatorcrypt gatorcrypt.o crypto.o $(LIBS)
	$(CC) -o gatordec gatordec.o crypto.o $(LIBS)
clean:
	rm *.o gatorcrypt gatordec
