/*
Stik's Security Module
dlist.h - header for doubly linked list
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

#ifndef WESTSIDES_DLIST_H
#define WESTSIDES_DLIST_H
#endif

// we want to try to make this LRU friendly...

typedef struct double_list_node
{
	struct double_list_node *next;
	struct double_list_node *prev;
	unsigned int key;
	void *data;
} dlistNode;

dlistNode *getDlistKey (dlistNode *start, unsigned int searchKey);
void insertDlistBefore (dlistNode *head, dlistNode *oldNode, dlistNode *newNode);
void insertDlistAfter (dlistNode *tail, dlistNode *oldNode, dlistNode *newNode);
void dlistDeleteNode (dlistNode **head, dlistNode **tail, dlistNode *delNode);
