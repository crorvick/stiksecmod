/*
Stik's Security Module
tree.h - header for tree ADT
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

typedef struct tree_node
{
	enum { red, black} color;
	treeNode *left;
	treeNode *right;
	treeNode *parent;
	__u32 key;
	void *data;
} treeNode;

treeNode *treeLeftRotate (treeNode *head, treeNode *x);
treeNode *getTreeKey (treeNode *head, __u32 searchKey);
treeNode *insertTree (treeNode *head, treeNode *newNode);
treeNode *treeDeleteNode (treeNode *head, __u32 deleteKey
);
