/*
Stik's Security Module
getnetsec.c - get the network sec settings
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
#include "../module/network.h"
#include "westsides.h"

void usage(void)
{
	printf("\nUsage:  getnetsec");
}

printAddr(unsigned int theAddr)
{
	printf("%d.", (theAddr % 256));
	theAddr = theAddr >> 8;
	printf("%d.", (theAddr % 256));
	theAddr = theAddr >> 8;
	printf("%d.", (theAddr % 256));
	theAddr = theAddr >> 8;
	printf("%d", (theAddr % 256));
}

void printNet(netPassAttr *tmpAttr)
{
	char labelName[1024];

	getHRLabel(tmpAttr->label, labelName);
	printf("Label: %s\n", labelName);
	printf("raddr: ");
	printAddr(tmpAttr->raddr);
	printf(" rmask: ");
	printAddr(tmpAttr->rmask);
	printf(" rminport: %d rmaxport: %d\n", tmpAttr->rport, tmpAttr->rrange);
	printf("laddr: ");
	printAddr(tmpAttr->laddr);
	printf(" lmask: ");
	printAddr(tmpAttr->lmask);
	printf(" lminport: %d lmaxport: %d\n", tmpAttr->lport, tmpAttr->lrange);
}

int main (int argc, char *argv[])
{
	int myFile, good = 0;
	unsigned int numEntries, ctr = 0;
	char *netStruct;
	netPassAttr *npa;

	if(argc > 1)
	{
		usage();
		return -1;
	}

	if((myFile = open(WESTSIDES_DEVICE,0)) < 0)
	{
		printf("Error opening device\n");
		return -5;
	}

	if(ioctl(myFile,8,(unsigned int)&numEntries) < 0)
	{
		printf("Error in ioctl\n");
		return -6;
	}
	printf("%d network entries\n", numEntries);

	if(numEntries < 1)
	{
		printf("No network security set.\n");
		return 0;
	}

	netStruct = (char *)malloc(numEntries * sizeof(netPassAttr));
	memset(netStruct, 0, numEntries * sizeof(netPassAttr));

	if(ioctl(myFile,9,(unsigned int)netStruct) < 0)
	{
		printf("Error in ioctl\n");
		return -6;
	}

	npa = (netPassAttr *)netStruct;
	while(ctr < numEntries)
	{
		printNet(npa);
		netStruct += sizeof(netPassAttr);
		npa = (netPassAttr *)netStruct;
		++ctr;
	}

	close(myFile);

	return 0;
}
