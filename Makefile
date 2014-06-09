all: main

main: main.o util.o hashtbl.o http_parser.o
	cc -o main util.o http_parser.o hashtbl.o main.o -lpcap -Wall

util.o: util.c util.h
	cc -o util.o -c util.c 

http_parser.o: http_parser.c http_parser.h
	cc -o http_parser.o -c http_parser.c 

hashtbl.o: hashtbl.c hashtbl.h
	cc -o hashtbl.o -c hashtbl.c 

main.o: main.c main.h hashtbl.h 
	cc -o main.o -c main.c -g 

test: test.o http_parser.o
	cc -o test http_parser.o test.o && ./test

test.o: test.c http_parser.h
	cc -o test.o -c test.c

clean:
	rm -rf *.o main a.out pcaps requests files

run:
	./main

d:
	make clean && make && make run
