/*
Stik's Security Module
getfilesec.c - get the file sec settings
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
#include "../module/file.h"
#include "../module/label.h"
#include "westsides.h"

void usage(void)
{
	printf("\nUsage:  getfilesec");
}

void printFile(passFileAttr *theAttr)
{
	char labelName[1024];

	printf("%s\n", theAttr->filename);
	getHRLabel(theAttr->label, labelName);
	printf("Label: %s  Flags:", labelName);
	if(theAttr->label & LABEL_READ)
		printf(" read");
	if(theAttr->label & LABEL_WRITE)
		printf(" write");
	if(theAttr->label & LABEL_EXEC)
		printf(" exec");
	if(theAttr->label & LABEL_APPEND)
		printf(" append");
	if(theAttr->label & LABEL_DELETE)
		printf(" delete");
	if(theAttr->label & LABEL_CREATE)
		printf(" create");
	if(theAttr->label & LABEL_FUNCTION)
		printf(" function");
	if(theAttr->label & LABEL_RECURSE)
		printf(" recurse");
	printf("\n");
}

int main (int argc, char *argv[])
{
	int myFile, good = 0;
	unsigned int numEntries, ctr = 0;
	char *fileStruct;
	passFileAttr *pfa;

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

	if(ioctl(myFile,10,(unsigned int)&numEntries) < 0)
	{
		printf("Error in ioctl\n");
		return -6;
	}
	printf("%d file entries\n", numEntries);

	if(numEntries < 1)
	{
		printf("No file security set.\n");
		return 0;
	}

	fileStruct = (char *)malloc(numEntries * sizeof(passFileAttr));
	memset(fileStruct, 0, numEntries * sizeof(passFileAttr));

	if(ioctl(myFile,11,(unsigned int)fileStruct) < 0)
	{
		printf("Error in ioctl\n");
		return -6;
	}

	pfa = (passFileAttr *)fileStruct;
	while(ctr < numEntries)
	{
		printFile(pfa);
		fileStruct += sizeof(passFileAttr);
		pfa = (passFileAttr *)fileStruct;
		++ctr;
	}

	close(myFile);

	return 0;
}
