/*
Stik's Security Module
global.c - global definitions for the module
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

#ifndef WESTSIDES_DLIST_H
#include "dlist.h"
#endif

#include <linux/spinlock.h>

// the heads of the lists
// we're really gonna whack these values - should put a lock around writing to them :)
listNode *pidListHead;
dlistNode *fileListHead, *fileListTail;
listNode *netListHead;

// reader writer locks for each list
rwlock_t pidListLock;
rwlock_t fileListLock;
rwlock_t netListLock;
