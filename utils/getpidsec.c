/*
Stik's Security Module
getpidsec.c - get a process sec settings
Copyright (C) 2003 Stik

This program is free software; you can redistribute it and/or modify it under th
e terms of the GNU General Public License as published by the Free Software Foun
dation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with thi
s program; if not, write to the Free Software Foundation, Inc., 59 Temple Place,
 Suite 330, Boston, MA 02111-1307 USA
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "../module/process.h"
#include "westsides.h"

void usage(void)
{
	printf("\nUsage:  protexec <pid>\n");
}

int main (int argc, char *argv[])
{
	int myFile, good = 0;
	procPass myPass;
	unsigned int newLabel, newPrivilege = 0;
	unsigned short myPid;
	char labelName[1024];

	if(argc < 1)
	{
		usage();
		return -1;
	}

	++argv;  // skip past argv0 - the binary name
	myPass.pid = atoi(*argv);

	myPass.label = 0;
	myPass.privileges = 0;

	if((myFile = open(WESTSIDES_DEVICE,0)) < 0)
	{
		printf("Error opening device\n");
		return -5;
	}

	if(ioctl(myFile,5,(unsigned int)&myPass) < 0)
	{
		printf("Error in ioctl\n");
		return -6;
	}
	close(myFile);

	getHRLabel(myPass.label, labelName);
	printf("PID: %d  Label: %s  Privilege: %u\n", myPass.pid, labelName, myPass.privileges);

	return 0;
}
