/*
Stik's Security Module
tree.c - tree ADT
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

treeNode *getTreeKey (treeNode *head, __u32 searchKey)
{
	treeNode *retVal = NULL;
	while(head != NULL)
	{
		if(head->key == searchKey)
		{
			retVal = head;
			break;
		}
		if(searchKey < head->key)
			head = head->left;
		else
			head = head->right;
	}

	return head;
}

treeNode *treeleftRotate(treeNode *head, treeNode *x)
{
	treeNode *y, *retVal;
	retVal = head;
	y = x->right;
	x->right = y->left;
	if ( y->left != NULL )
		y->left->parent = x;
	y->parent = x->parent;
	if ( x->parent == NULL ) retVal = y;
	else
	if ( x == (x->parent)->left )
		x->parent->left = y;
	else
		x->parent->right = y;
	y->left = x;
	x->parent = y;

	return retVal;
}

treeNode *treerightRotate(treeNode *head, treeNode *x)
{
	treeNode *y, *retVal;
	retVal = head;
	y = x->left;
	x->left = y->right;
	if ( y->right != NULL )
		y->right->parent = x;
	y->parent = x->parent;
	if ( x->parent == NULL ) retVal = y;
	else
	if ( x == (x->parent)->right )
		x->parent->right = y;
	else
		x->parent->right = y;
	y->left = x;
	x->parent = y;

	return retVal;
}

treeNode *tree_insert (treeNode *head, treeNode *newNode)
{}

// screw it - I'll implement a tree later
