/*
Stik's Security Module
protexec.c - run a process with a label
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
#include "../module/privilege.h"
#include "../module/label.h"
#include "westsides.h"

void usage(void)
{
	printf("\nUsage:  protexec <-l label> [-p privileges] <file>\n\n");
}

int main (int argc, char *argv[])
{
	int myFile, good = 0;
	procPass myPass;
	unsigned int newLabel, newPrivilege = 0;
	unsigned int addLabel = 0;

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
			if(newLabel < 1)
			{
				printf("Label not defined.");
				return -1;
			}
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
		else if(!strncmp(*argv, "-f", 2))
		{
			addLabel += LABEL_FUNCTION;
		}
		else if(!strncmp(*argv, "-c", 2))
		{
			addLabel += LABEL_CREATE;
		}
		else if(!strncmp(*argv, "-a", 2))
		{
			addLabel += LABEL_APPEND;
		}
		else if(!strncmp(*argv, "-p", 2))
		{
			++argv;
			if(*argv == NULL)
			{
				usage();
				return -3;
			}
			newPrivilege = resolvePrivilege(*argv);
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
	myPass.label = newLabel << 8;
	myPass.label += addLabel;
	myPass.privileges = newPrivilege;
	myPass.pid = getpid();
	//printf("got here, pid:%d\n", myPass.pid);

	if((myFile = open(WESTSIDES_DEVICE,0)) < 0)
	{
		printf("Error opening device\n");
		return -5;
	}

	if(ioctl(myFile,0,(unsigned int)&myPass) < 0)
	{
		printf("Error in ioctl\n");
		return -6;
	}
	close(myFile);

	//printf("got here: %s\n", *argv);
	//if(*(argv + 1) == NULL)
		//printf("and the next argv is NULL\n");
	
	execve(*argv, argv, NULL);

	return 0;
}
