/*
Stik's Security Module
dlist.c - doubly linked list 
Copyright (C) 2003 Stik

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#ifndef WESTSIDES_DLIST_H
#include "dlist.h"
#endif

#ifndef NULL
#define NULL 0x0
#endif

dlistNode *getDlistKey (dlistNode *start, unsigned int searchKey)
{
	dlistNode *retVal = NULL;
	while (start != NULL)
	{
		if(start->key == searchKey)
		{
			retVal = start;
			break;
		}
		start = start->next;
	}

	return retVal;
}

void dlistInsertBefore (dlistNode **head, dlistNode **tail, dlistNode *oldNode, dlistNode *newNode)
{
	if (*head == NULL)
	{
		*head = newNode;
		*tail = newNode;
		return;
	}

	if (oldNode->prev == NULL)
		*head = newNode;
	newNode->prev = oldNode->prev;
	oldNode->prev = newNode;
	newNode->next = oldNode;
}

void dlistInsertAfter (dlistNode **head, dlistNode **tail, dlistNode *oldNode, dlistNode *newNode)
{
	if (*head == NULL)
	{
		*head = newNode;
		*tail = newNode;
		return;
	}

	if (oldNode->next == NULL)
		*tail = newNode;
	newNode->next = oldNode->next;
	oldNode->next = newNode;
	newNode->prev = oldNode;
}

void dlistDeleteNode (dlistNode **head, dlistNode **tail, dlistNode *delNode)
{
	if(delNode->prev == NULL)
		*head=delNode->next;
	else
		delNode->prev->next = delNode->next;
	if(delNode->next == NULL)
		*tail=delNode->prev;
	else
		delNode->next->prev = delNode->prev;
}

