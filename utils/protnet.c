/*
Stik's Security Module
protnet.c - set sec on a network object
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
#include "../module/network.h"
#include "westsides.h"

void usage(void)
{
	printf("\nUsage:  protnet <-raddr remoteaddr/mask> <-laddr localaddr/mask>\n		<-rport remoteport/range> <-lport localport/range> <-L label>\n\n");
}

int main (int argc, char *argv[])
{
	int myFile, good = 0, blockAll = 0;
	netPassAttr myPass;
	unsigned int localAddr = 0, localMask = 4294967295, remoteAddr = 0, remoteMask = 4294967295;
	unsigned int label;
	unsigned short localPort = 0, localRange = 65535, remotePort = 0, remoteRange = 65535;
	unsigned int tmpInt;
	char *tmpStr, *tmpStr2, *tmpStr3;

	if(argc < 3)
	{
		usage();
		return -1;
	}

	++argv;  // skip past argv0 - the binary name
	while(*argv != NULL)
	{
		if(!strncmp(*argv, "-laddr", 6))
		{
			++argv;
			if(*argv == NULL)
			{
				usage();
				return -2;
			}
			// tmpStr is the address
			tmpStr = (char *)strtok(*argv, "/");
			// tmpStr2 is the mask
			tmpStr2 = (char *)strtok(NULL, "/");

			tmpStr3 = (char *)strtok(tmpStr, ".");
			tmpInt = atoi(tmpStr3);
			localAddr += (tmpInt);
			tmpStr3 = (char *)strtok(NULL, ".");
			tmpInt = atoi(tmpStr3);
			localAddr += (tmpInt << 8);
			tmpStr3 = (char *)strtok(NULL, ".");
			tmpInt = atoi(tmpStr3);
			localAddr += (tmpInt << 16);
			tmpStr3 = (char *)strtok(NULL, ".");
			tmpInt = atoi(tmpStr3);
			localAddr += (tmpInt << 24);

			if(tmpStr2 != NULL)
			{
				localMask = 0;
				tmpStr3 = (char *)strtok(tmpStr2, ".");
				tmpInt = atoi(tmpStr3);
				localMask += (tmpInt);
				tmpStr3 = (char *)strtok(NULL, ".");
				tmpInt = atoi(tmpStr3);
				localMask += (tmpInt << 8);
				tmpStr3 = (char *)strtok(NULL, ".");
				tmpInt = atoi(tmpStr3);
				localMask += (tmpInt << 16);
				tmpStr3 = (char *)strtok(NULL, ".");
				tmpInt = atoi(tmpStr3);
				localMask += (tmpInt << 24);
			}
					
			--blockAll;
		}
		else if(!strncmp(*argv, "-L", 2))
		{
			++argv;
			if(*argv == NULL)
			{
				usage();
				return -2;
			}
			good = 1;
			label = resolveLabel(*argv);
			if(label < 1)
			{
				printf("Label is not defined.\n");
				return -1;
			}
			++blockAll;
		}
		else if(!strncmp(*argv, "-raddr", 6))
		{
			++argv;
			if(*argv == NULL)
			{
				usage();
				return -2;
			}
			// tmpStr is the address
			tmpStr = (char *)strtok(*argv, "/");
			// tmpStr2 is the mask
			tmpStr2 = (char *)strtok(NULL, "/");

			tmpStr3 = (char *)strtok(tmpStr, ".");
			tmpInt = atoi(tmpStr3);
			remoteAddr += (tmpInt);
			tmpStr3 = (char *)strtok(NULL, ".");
			tmpInt = atoi(tmpStr3);
			remoteAddr += (tmpInt << 8);
			tmpStr3 = (char *)strtok(NULL, ".");
			tmpInt = atoi(tmpStr3);
			remoteAddr += (tmpInt << 16);
			tmpStr3 = (char *)strtok(NULL, ".");
			tmpInt = atoi(tmpStr3);
			remoteAddr += (tmpInt << 24);

			if(tmpStr2 != NULL)
			{
				remoteMask = 0;
				tmpStr3 = (char *)strtok(tmpStr2, ".");
				tmpInt = atoi(tmpStr3);
				remoteMask += (tmpInt);
				tmpStr3 = (char *)strtok(NULL, ".");
				tmpInt = atoi(tmpStr3);
				remoteMask += (tmpInt << 8);
				tmpStr3 = (char *)strtok(NULL, ".");
				tmpInt = atoi(tmpStr3);
				remoteMask += (tmpInt << 16);
				tmpStr3 = (char *)strtok(NULL, ".");
				tmpInt = atoi(tmpStr3);
				remoteMask += (tmpInt << 24);
			}
					
			--blockAll;
		}
		else if(!strncmp(*argv, "-rport", 6))
		{
			++argv;
			if(*argv == NULL)
			{
				usage();
				return -2;
			}
			// tmpStr is the port
			tmpStr = (char *)strtok(*argv, "/");
			// tmpStr2 is the range
			tmpStr2 = (char *)strtok(NULL, "/");

			remotePort = atoi(tmpStr);
			if(tmpStr2 != NULL)
				remoteRange = atoi(tmpStr2);
			else
				remoteRange = remotePort;
			--blockAll;
		}
		else if(!strncmp(*argv, "-lport", 6))
		{
			++argv;
			if(*argv == NULL)
			{
				usage();
				return -2;
			}
			// tmpStr is the port
			tmpStr = (char *)strtok(*argv, "/");
			// tmpStr2 is the range
			tmpStr2 = (char *)strtok(NULL, "/");

			localPort = atoi(tmpStr);
			if(tmpStr2 != NULL)
				localRange = atoi(tmpStr2);
			else
				localRange = localPort;
			--blockAll;
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

	if(blockAll > 0)
	{
		localRange = 0;
		remoteRange = 0;
	}

	memset(&myPass, 0, sizeof(netPassAttr));
	myPass.label = label << 8;
	myPass.laddr = localAddr;
	myPass.lmask = localMask;
	myPass.lport = localPort;
	myPass.lrange = localRange;
	myPass.raddr = remoteAddr;
	myPass.rmask = remoteMask;
	myPass.rport = remotePort;
	myPass.rrange = remoteRange;

	if((myFile = open(WESTSIDES_DEVICE,0)) < 0)
	{
		printf("Error opening device\n");
		return -5;
	}

	if(ioctl(myFile,2,(unsigned int)&myPass) < 0)
	{
		printf("Error in ioctl\n");
		return -6;
	}
	close(myFile);

	return 0;
}
