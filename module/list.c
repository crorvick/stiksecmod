/*
Stik's Security Module
list.c - linked list
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

#ifndef WESTSIDES_LIST_H
#include "list.h"
#endif

#ifndef WESTSIDES_LIST_C
#define WESTSIDES_LIST_C
#endif

#ifndef NULL
#define NULL 0x0
#endif

listNode *getListKey (listNode *head, unsigned int searchKey)
{
	listNode *retVal = NULL;
	while ( head != NULL )
	{
		if (head->key == searchKey)
		{
			retVal = head;
			break;
		}
		head = head->next;
	}

	return retVal;
}

listNode *getListMaskKey (listNode *head, unsigned int searchKey, unsigned int maskKey)
{
	listNode *retVal = NULL;
	while ( head != NULL )
	{
		if ((maskKey & head->key) == (searchKey & maskKey))
		{
			retVal = head;
			break;
		}
		head = head->next;
	}

	return retVal;
}

listNode *listInsert (listNode *head, listNode *newNode)
{
	newNode->next = head;
	return newNode;
}

listNode *listDelete (listNode *head, unsigned int deleteKey)
{
	listNode *retVal = head;
	if(head == NULL)
		return head;
	if(deleteKey == head->key)
		return head->next;
	while (head->next != NULL)
	{
		if(deleteKey == head->next->key)
		{
			head->next = head->next->next;
			break;
		}
		head = head->next;
	}

	return retVal;
}
