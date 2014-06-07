all: main

main: main.o hashtbl.o 
	cc -o main hashtbl.o main.o -lpcap -Wall

hashtbl.o: hashtbl.c hashtbl.h
	cc -o hashtbl.o -c hashtbl.c 

main.o: main.c hashtbl.h
	cc -o main.o -c main.c -g

clean:
	rm -rf *.o main a.out pcaps https files

run:
	./main test.pcap

d:
	make clean && make && make run
