all:	stiksec.o

stiksec.o:	module.o syshook.o
	$(LD) -r $^ -o $@

module.o:
	gcc -c -O3 -Wall -I/usr/src/linux/include -o module.o module.c

syshook.o:
	gcc -c -o syshook.o syshook.S

clean:
	rm *.o
