CFLAGS=-Wall
LDLIBS=-lssh -lssh_threads

all: pcp

pcp: pcp.o

clean:
	rm -f *.o pcp
