all:	protexec protnet protfile getfilesec getpidsec getnetsec delfilesec delnetsec loadtemplate

protexec:	westsides.o protexec.o
	gcc -o protexec westsides.o protexec.o

protexec.o:
	gcc -c -o protexec.o protexec.c

protfile:	westsides.o protfile.o
	gcc -o protfile westsides.o protfile.o

protfile.o:
	gcc -c -o protfile.o protfile.c

loadtemplate:	westsides.o loadtemplate.o
	gcc -o loadtemplate westsides.o loadtemplate.o

loadtemplate.o:
	gcc -c -o loadtemplate.o loadtemplate.c

protnet:	westsides.o protnet.o
	gcc -o protnet westsides.o protnet.o

protnet.o:
	gcc -c -o protnet.o protnet.c

delfilesec:	westsides.o delfilesec.o
	gcc -o delfilesec westsides.o delfilesec.o

delfilesec.o:
	gcc -c -o delfilesec.o delfilesec.c

delnetsec.o:
	gcc -c -o delnetsec.o delnetsec.c

delnetsec:	westsides.o delnetsec.o
	gcc -o delnetsec westsides.o delnetsec.o

getpidsec:	westsides.o
	gcc -o getpidsec getpidsec.c westsides.o

getnetsec:	westsides.o
	gcc -o getnetsec getnetsec.c westsides.o

getfilesec:	westsides.o
	gcc -o getfilesec getfilesec.c westsides.o

westsides.o:
	gcc -c -o westsides.o westsides.c

clean:
	rm -f *.o
