/*
Stik's Security Module
westside.c - common functions for the utils
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
#include <unistd.h>

#define LABEL_FILE "/etc/westsides/Label"

unsigned int resolveLabel(const char *labelText)
{
	FILE *myFile;
	char line[1024];
	char labelName[1024];
	unsigned int labelNum = 0;
	char *tmp;

	strncpy(labelName, labelText, 1024);
	labelName[1023] = 0;

	myFile = fopen(LABEL_FILE, "r");
	while(fgets(line,1024,myFile) != NULL)
	{
		tmp = (char *)strtok(line," ");
		if(!strncmp(tmp,labelName,1024))
		{
			tmp = (char *)strtok(NULL," ");
			labelNum = (unsigned int)atoi(tmp);
			break;
		}
	}
	fclose(myFile);

	return labelNum;
} 

void getHRLabel(unsigned int theLabel, char *labelName)
{
	FILE *myFile;
	char line[1024];
	char *tmp, *tmp2;
	unsigned int label = (theLabel >> 8);

	myFile = fopen(LABEL_FILE, "r");
	while(fgets(line,1024,myFile) != NULL)
	{
		memset(labelName, 0, 1024);
		tmp = (char *)strtok(line," ");
		tmp2 = (char *)strtok(NULL," ");
		if(label == (unsigned int)atoi(tmp2))
		{
			strncpy(labelName, tmp, strlen(tmp));
			break;
		}
	}
	fclose(myFile);
} 

unsigned int resolvePrivilege(const char *privText)
{
	return (unsigned int)atoi(privText);
}
