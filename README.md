tcp-reassembler
===============

[compile for windows on linux](http://www.blogcompiler.com/2010/07/11/compile-for-windows-on-linux/)

Makefile syntax: 
all: main

main: main.o util.o hashtbl.o http_parser.o
	cc -std=c99 -o main.exe util.o http_parser.o hashtbl.o main.o -lwpcap -Wall

util.o: util.c util.h
	cc -std=c99 -o util.o -c util.c 

http_parser.o: http_parser.c http_parser.h
	cc -std=c99 -o http_parser.o -c http_parser.c 

hashtbl.o: hashtbl.c hashtbl.h
	cc -std=c99 -o hashtbl.o -c hashtbl.c 

main.o: main.c main.h hashtbl.h 
	cc -std=c99 -o main.o -c main.c -g 

test: test.o http_parser.o
	cc -std=c99 -o test http_parser.o test.o && ./test

test.o: test.c http_parser.h
	cc -std=c99 -o test.o -c test.c

clean:
	rm -rf *.o main a.out pcaps requests files

run:
	./main

d:
	make clean && make && make run

