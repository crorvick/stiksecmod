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
#include "../module/network.h"
#include "westsides.h"

void usage(void)
{
	printf("\nUsage:  loadtemplate <templatefile>\n");
}

int main (int argc, char *argv[])
{
	int myFile, good = 0;
	passFileAttr myPass;
	netPassAttr netPass;
	unsigned int addLabel = 0;
	unsigned int newLabel;
	FILE *myFile2;
        char line[1024];
	char fileName[1024];
        char labelName[1024];
        unsigned int labelNum;
        char *tmp, *tmpLA, *tmpRA, *tmpLP, *tmpRP;
	unsigned int localAddr = 0, localMask = 4294967295, remoteAddr = 0, remoteMask = 4294967295;
	unsigned int label;
	unsigned short localPort = 0, localRange = 65535, remotePort = 0, remoteRange = 65535;
	unsigned int tmpInt;
	char *tmpStr, *tmpStr2, *tmpStr3;

	strncpy(fileName, argv[1], 1024);
	fileName[1023] = 0;

	if(argc != 2)
	{
		usage();
		return -1;
	}

	if((myFile = open(WESTSIDES_DEVICE,0)) < 0)
	{
		printf("Error opening device\n");
		return -5;
	}

        myFile2 = fopen(fileName, "r");

        while(fgets(line,1024,myFile2) != NULL)
        {
		tmp = (char *)strtok(line,":");
		if(!strncmp(tmp,"file",4))
		{
			memset(&myPass, 0, sizeof(myPass));

                	tmp = (char *)strtok(NULL,":");
			strncpy(myPass.filename,tmp,1024);

                	tmp = (char *)strtok(NULL,":");
			newLabel = resolveLabel(tmp);
			if(newLabel < 1)
			{
				printf("Label %s not defined.  Skipping rule.", tmp);
				continue;
			}

			addLabel = 0;
			tmp = (char *)strtok(NULL,":");
			if(tmp == NULL)
				addLabel = 0;
			else
			{
				while(*tmp != 0)
				{
					switch (*tmp)
					{
						case 'r':
						addLabel += LABEL_READ;
						break;
						;;
	
						case 'w':
						addLabel += LABEL_WRITE;
						break;
						;;

						case 'x':
						addLabel += LABEL_EXEC;
						break;
						;;
	
						case 'd':
						addLabel += LABEL_DELETE;
						break;
						;;
	
						case 'c':
						addLabel += LABEL_CREATE;
						break;
						;;
	
						case 'a':
						addLabel += LABEL_APPEND;
						break;
						;;
	
						case 'f':
						addLabel += LABEL_FUNCTION;
						break;
						;;
	
						case 'R':
						addLabel += LABEL_RECURSE;
						break;
						;;

						default:
						break;
						;;
					}
					++tmp;
				}
			}

			myPass.label = (newLabel << 8) + addLabel;

			if(ioctl(myFile,1,(unsigned int)&myPass) < 0)
			{
				printf("Error in ioctl\n");
				return -6;
			}
		}

		else if(!strncmp(tmp,"net",3))
		{
			localAddr = 0; localMask = 4294967295;
			remoteAddr = 0; remoteMask = 4294967295;
			localPort = 0; localRange = 65535;
			remotePort = 0; remoteRange = 65535;

			tmpLA = (char *)strtok(NULL, ":");
			tmpLP = (char *)strtok(NULL, ":");
			tmpRA = (char *)strtok(NULL, ":");
			tmpRP = (char *)strtok(NULL, ":");
			tmp = (char *)strtok(NULL, ":");

			// tmpStr is the address
			tmpStr = (char *)strtok(tmpLA, "/");
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
					
			// tmpStr is the address
			tmpStr = (char *)strtok(tmpRA, "/");
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
					
			if(tmpRP != NULL)
			{
				// tmpStr is the port
				tmpStr = (char *)strtok(tmpRP, "/");
				// tmpStr2 is the range
				tmpStr2 = (char *)strtok(NULL, "/");

				remotePort = atoi(tmpStr);
				if(tmpStr2 != NULL)
					remoteRange = atoi(tmpStr2);
				else
					remoteRange = remotePort;
			}

			if(tmpLP != NULL)
			{
				// tmpStr is the port
				tmpStr = (char *)strtok(tmpLP, "/");
				// tmpStr2 is the range
				tmpStr2 = (char *)strtok(NULL, "/");

				localPort = atoi(tmpStr);
				if(tmpStr2 != NULL)
					localRange = atoi(tmpStr2);
				else
					localRange = localPort;
			}

			memset(&netPass, 0, sizeof(netPassAttr));

			newLabel = resolveLabel(tmp);
			netPass.label = newLabel << 8;
			netPass.laddr = localAddr;
			netPass.lmask = localMask;
			netPass.lport = localPort;
			netPass.lrange = localRange;
			netPass.raddr = remoteAddr;
			netPass.rmask = remoteMask;
			netPass.rport = remotePort;
			netPass.rrange = remoteRange;

			if(ioctl(myFile,2,(unsigned int)&netPass) < 0)
			{
				printf("Error in ioctl\n");
				return -6;
			}
		}
        }

        fclose(myFile2);
	close(myFile);

	return 0;
}
