/*
Stik's Security Module
list.h - header for a linked list
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
#define WESTSIDES_LIST_H
#endif

typedef struct list_node
{
	struct list_node *next;
	unsigned int key;
	void *data;
} listNode;

// find the node with key searchKey
listNode *getListKey (listNode *head, unsigned int searchKey);

// find the node with key searchKey
listNode *getListMaskKey (listNode *head, unsigned int searchKey, unsigned int maskKey);

// insert newNode before head, return the new head
listNode *listInsert (listNode *head, listNode *newNode);

// delete key deleteKey return the new head
listNode *listDelete (listNode *head, unsigned int deleteKey);
