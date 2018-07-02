# use -lm option after the source file when using math function and gcc to compile
meltdown: meltdown.o
	gcc -o meltdown  -O2 -msse2  meltdown.o  -lm
meltdown.o: meltdown.c
	gcc -c meltdown.c 
clean:
	rm -f meltdown.o meltdown rdtscp.h
