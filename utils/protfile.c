/*
Stik's Security Module
protfile.c - set sec on a file
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
#include <fcntl.h>
#include <stdio.h>
#include "../module/file.h"
#include "../module/label.h"
#include "westsides.h"

void usage(void)
{
	printf("\nUsage:  protfile <-r|-w|-x|-d> <-l label> [-R] <file>\n\n");
}

int main (int argc, char *argv[])
{
	int myFile, good = 0;
	passFileAttr myPass;
	unsigned int addLabel = 0;
	unsigned int newLabel, newPrivilege = 0;

	if(argc < 3)
	{
		usage();
		return -1;
	}

	++argv;  // skip past argv0 - the binary name
	while(*argv != NULL)
	{
		if(!strncmp(*argv, "-l", 2))
		{
			//printf("got -l\n");
			++argv;
			if(*argv == NULL)
			{
				usage();
				return -2;
			}
			newLabel = resolveLabel(*argv);
			//printf("nL:%d\n",newLabel);
			good = 1;
		}
		else if(!strncmp(*argv, "-r", 2))
		{
			addLabel += LABEL_READ;
		}
		else if(!strncmp(*argv, "-w", 2))
		{
			addLabel += LABEL_WRITE;
		}
		else if(!strncmp(*argv, "-d", 2))
		{
			addLabel += LABEL_DELETE;
		}
		else if(!strncmp(*argv, "-x", 2))
		{
			addLabel += LABEL_EXEC;
		}
		else if(!strncmp(*argv, "-R", 2))
		{
			addLabel += LABEL_RECURSE;
		}
		else
			break;
		++argv;
	}
	if(!good)
	{
		usage();
		return -4;
	}

	memset(&myPass, 0, sizeof(myPass));
	myPass.label = (newLabel << 8) + addLabel;
	strncpy(myPass.filename,*argv,1024);

	if((myFile = open(WESTSIDES_DEVICE,0)) < 0)
	{
		printf("Error opening device\n");
		return -5;
	}

	if(ioctl(myFile,1,(unsigned int)&myPass) < 0)
	{
		printf("Error in ioctl\n");
		return -6;
	}
	close(myFile);

	return 0;
}
