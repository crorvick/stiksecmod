/*
Stik's Security Module
util.c - utility functions for the module
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

#ifndef WESTSIDES_NET
#include "network.h"
#endif

#ifndef WESTSIDES_PRIVILEGE
#include "privilege.h"
#endif

#ifndef WESTSIDES_LABEL
#include "label.h"
#endif

#ifndef WESTSIDES_FILE
#include "file.h"
#endif

#ifndef WESTSIDES_PROCESS
#include "process.h"
#endif

#include <linux/in.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/spinlock.h>

void testNames(void)
{
	struct fs_struct *tmpFs;
	struct dentry *tmpDc;
	struct vfsmount *tmpVm;
	int ctr;

	printk("Testing...\n");
	tmpFs = current->fs;
	if(tmpFs == NULL)
		return;
	printk("tmpFs is good.\n");
	tmpDc = tmpFs->pwd;
	if(tmpDc == NULL)
		return;
	printk("tmpDc=pwd is good.\n");
	if(tmpDc->d_name.name == NULL)
		return;
	printk("d_name.name = %s\n", tmpDc->d_name.name);
	ctr = 0;
	while(tmpDc->d_parent != NULL && ctr < 10)
	{
		tmpDc = tmpDc->d_parent;
		if(tmpDc->d_name.name != NULL)
			printk("d_name.name = %s\n", tmpDc->d_name.name);
		++ctr;
	}	
	tmpVm = tmpFs->pwdmnt;
	tmpDc = tmpVm->mnt_mountpoint;
	printk("vfsmnt dentry: %s\n",tmpDc->d_name.name);
	return;
}


int localNetworkAccess(unsigned int processLabel, struct sockaddr *uservaddr)
{
        listNode *tmpListNode;
        netAttr *tmpNetAttr;
        struct sockaddr_in *tmpSockaddr;
	struct in_addr *tmpSinAddr;
        unsigned int addrRequest;
        unsigned short portRequest;
	int retVal;

	// handles inverse networking with LABEL_FUNCTION
	if(processLabel & LABEL_FUNCTION)
		retVal = 0;
	else
		retVal = 1;

	read_lock(&netListLock);
        if((tmpListNode = getListMaskKey(netListHead, processLabel, LABEL_MASK)) != NULL)
        {
                // we found a match in the network label list bump bump bump bump, that's the sound...
                tmpListNode = (listNode *)(tmpListNode->data);
                while(tmpListNode != NULL)
                {
                        // now for connect() we compare the r's of the netAttr vs uservaddr
                        // n.b. this is only IPv4 code here
                        tmpNetAttr = (netAttr *)tmpListNode->data;
                        tmpSockaddr = (struct sockaddr_in *)uservaddr;
                        portRequest = ntohs(tmpSockaddr->sin_port);
			tmpSinAddr = (struct in_addr *)&(tmpSockaddr->sin_addr);
                        addrRequest = (unsigned int)(tmpSinAddr->s_addr);


                        // first check the address
                        if((addrRequest & tmpNetAttr->lmask) == (tmpNetAttr->laddr & tmpNetAttr->lmask))
                        {
                                // now check the port
                                if((portRequest >= tmpNetAttr->lport) && (portRequest <= tmpNetAttr->lrange))
                                {
                                        // okay let it happen
					// inverse is block this
					read_unlock(&netListLock);
                                        return retVal;
                                }
                        }
                        // not a match this time, check the next netAttr for this label
                        tmpListNode = tmpListNode->next;
                }
                // we've got a label, but no address match.  under default mode this is blocked
		// under inverse this is allowed
		read_unlock(&netListLock);
                return (!retVal);
        }
        // this label is not network restricted
	// allow under all conditions
	read_unlock(&netListLock);
        return 1;
}

int remoteNetworkAccess(unsigned int processLabel, struct sockaddr *uservaddr)
{
	listNode *tmpListNode;
	netAttr *tmpNetAttr;
	struct sockaddr_in *tmpSockaddr;
	struct in_addr *tmpSinAddr;
	unsigned int addrRequest;
	unsigned int portRequest;
	int retVal;

	// handles inverse networking with LABEL_FUNCTION
	if(processLabel & LABEL_FUNCTION)
		retVal = 0;
	else
		retVal = 1;

	read_lock(&netListLock);
	if((tmpListNode = getListMaskKey(netListHead, processLabel, LABEL_MASK)) != NULL)
	{
		// we found a match in the network label list bump bump bump bump, that's the sound...
		tmpListNode = (listNode *)(tmpListNode->data);
		while(tmpListNode != NULL)
		{
			// now for connect() we compare the r's of the netAttr vs uservaddr
			// n.b. this is only IPv4 code here
			tmpNetAttr = (netAttr *)tmpListNode->data;
			tmpSockaddr = (struct sockaddr_in *)uservaddr;
			portRequest = ntohs(tmpSockaddr->sin_port);
			tmpSinAddr = (struct in_addr *)&(tmpSockaddr->sin_addr);
                        addrRequest = (unsigned int)(tmpSinAddr->s_addr);

			// first check the address
			if((addrRequest & tmpNetAttr->rmask) == (tmpNetAttr->raddr & tmpNetAttr->rmask))
			{
				// now check the port
				if((portRequest >= tmpNetAttr->rport) && (portRequest <= tmpNetAttr->rrange))
				{
					// okay let it happen
					// inverse is deny
					read_unlock(&netListLock);
					return retVal;
				}
			}
			// not a match this time, check the next netAttr for this label
			tmpListNode = tmpListNode->next;
		}
		// we've got a label, but no address match.  under default mode this is blocked
		// under inverse this mode is allowed
		read_unlock(&netListLock);
		return (!retVal);
	}
	// this label is not network restricted
	read_unlock(&netListLock);
	return 1;
}

int fileLabelAccess(unsigned int processLabel, unsigned int fileLabel, unsigned int accessType)
{
	if((fileLabel & accessType) ^ (processLabel & accessType))
		return 0;
	return 1;
}

int checkPrivilege(unsigned int privVector)
{
        listNode *tempNode;
        procAttr *tempProcAttr;
	int retVal = 1;

	read_lock(&pidListLock);
	// search for this process to see if it is protected
        if((tempNode = getListKey(pidListHead, current->pid)) == NULL)
	{
		// unprotected, return 1 for sucess to the module
                retVal = 1;
		goto privExit;
	}
        tempProcAttr = (procAttr *)(tempNode->data);
	
	// check to see if this process is restricted from this privilege
        if((privVector & PRIVILEGE_MASK) & (tempProcAttr->privileges))
	{
		retVal = 0;
		goto privExit;
	}

	// see if we have the DOU flag set and drop the privilege if so
	if((privVector & DOU_MASK) & (tempProcAttr->privileges))
		(tempProcAttr->privileges) &= (privVector & PRIVILEGE_MASK);
	
privExit:
	read_unlock(&pidListLock);
	return retVal;
	
}

int realFileName(const char *origFilename, char *realFilename, int fileNameLen)
{
        const char *fileNamePtr = origFilename;
        char *realFilePtr = realFilename;
	int retVal = 0, fileCtr = 1;
	int error;
	struct vfsmount *pwdmnt, *rootmnt;
	struct dentry *pwd, *root;
	char *page; 
	unsigned long len;
	char * cwd = NULL;

        if(*fileNamePtr == 0)
	{
                // not a real filename let the kernel return an error
                goto filenamedone;
	}

	// we need to zero out the realFilename 1st
	memset(realFilename, 0, fileNameLen);

        if(*fileNamePtr == '/')
        {
                *realFilePtr = '/';
                ++realFilePtr;
		++fileCtr;
                while(*fileNamePtr == '/')
                        ++fileNamePtr;
        }
        else
        {
                // we have to prepend the cwd of the process
		// getcwd is the userspace schtick, gotta remember how 
		// to do it in the kernel
		// Thank you sys_getcwd!

		// a userspace page?  I dunno...
		page = (char *) __get_free_page(GFP_USER);

		if (!page)
			return -1;

		read_lock(&current->fs->lock);
		pwdmnt = mntget(current->fs->pwdmnt);
		pwd = dget(current->fs->pwd);
		rootmnt = mntget(current->fs->rootmnt);
		root = dget(current->fs->root);
		read_unlock(&current->fs->lock);

		error = -1;
		/* Has the current directory has been unlinked? */
		spin_lock(&dcache_lock);
		if (pwd->d_parent == pwd || !list_empty(&pwd->d_hash)) {

			cwd = __d_path(pwd, pwdmnt, root, rootmnt, page, PAGE_SIZE);
			spin_unlock(&dcache_lock);

			error = -1;
			len = PAGE_SIZE + page - cwd;
			if (len >= 0) {
				error = len;
			}
		} else
			spin_unlock(&dcache_lock);
		dput(pwd);
		mntput(pwdmnt);
		dput(root);
		mntput(rootmnt);
		free_page((unsigned long) page);
		if(error < 0)
			return error;
			
		if(cwd != NULL)
			strncpy(realFilePtr,cwd,error);

		while(*realFilePtr != 0) { ++realFilePtr; ++fileCtr; }
		*realFilePtr = '/';  ++realFilePtr;  ++fileCtr;
        }

        // now for the good shit
        for(;;)
        {
                if(*fileNamePtr == '/')
                {
                        *realFilePtr = '/';
                        ++realFilePtr;
			++fileCtr;
                        while(*fileNamePtr == '/')
                                ++fileNamePtr;
                }
                else if (*fileNamePtr == '.')
                {
                        // ooh something special might be going on
                        ++fileNamePtr;
                        if(*fileNamePtr == '/')
                        {
                                // just a ./ don't do shit :)
                                ++fileNamePtr;
                                while(*fileNamePtr == '/')
                                        ++fileNamePtr;
                        }
			else if (*fileNamePtr == 0)
			{
				// last . don't do shit
				retVal = 1;
				goto filenamedone;
			}
                        else if (*fileNamePtr == '.')
                        {
                                // two dots, lets see if its a filename
                                if(*(fileNamePtr+1) != '/' && *(fileNamePtr+1) != 0)
                                {
                                        // write the 1st one since we're already pointing to the second
                                        *realFilePtr = '.';
                                        ++realFilePtr;
					++fileCtr;
                                        // go until we're done with the path
                                        while(*fileNamePtr != '/')
                                        {
                                                *realFilePtr = *fileNamePtr;
                                                if((*fileNamePtr == 0) || (fileCtr >= fileNameLen))
						{
							retVal = 1;
                                                        goto filenamedone;
						}
                                                ++realFilePtr;
						++fileCtr;
                                                ++fileNamePtr;
                                        }
                                }
                                else
                                {
                                        // this really is two dots, step back through the realFileName to erase the last path
                                        // already at just "/" is covered since we are already at position 2 by writing "/"
					// namePtr is the 2nd .
					++fileNamePtr;
					if(*(fileNamePtr) == '/')
						++fileNamePtr;

					// this puts us at /, we need to move back past / so long as this isn't the 1st slash
                                        --realFilePtr;
					--fileCtr;
					if(fileCtr != 1)
					{
						*realFilePtr = 0;
						--realFilePtr;
						--fileCtr;
					}

                                        while(*realFilePtr != '/')
					{
						*realFilePtr = 0;
                                                --realFilePtr;
						--fileCtr;
					}
                                        // we went too far back by one
                                        ++realFilePtr;
					++fileCtr;
                                }
                        }
			else 
			// one dot and then some symbol, grab the path
			{
                                        // write the 1st one since we're already pointing to the second
                                        *realFilePtr = '.';
                                        ++realFilePtr;
					++fileCtr;
                                        // go until we're done with the path
                                        while(*fileNamePtr != '/')
                                        {
                                                *realFilePtr = *fileNamePtr;
                                                if((*fileNamePtr == 0) || (fileCtr >= fileNameLen))
						{
							retVal = 1;
                                                        goto filenamedone;
						}
                                                ++realFilePtr;
						++fileCtr;
                                                ++fileNamePtr;
                                        }
                         }
			
                }
                // Think these bounds are right?  we might already be dereferencing out of bounds addresses
                else if ((*fileNamePtr == 0) || (fileCtr >= fileNameLen))
		{
			retVal = 1;
			goto filenamedone;
		}
                else
                {
                        // just a regular character - of course we should look for dots afterwords so they don't get picked up above
                        *realFilePtr = *fileNamePtr;
                        ++realFilePtr;
			++fileCtr;
                        ++fileNamePtr;
                        while(*fileNamePtr == '.')
                        {
                                *realFilePtr = *fileNamePtr;
                                ++realFilePtr;
				++fileCtr;
                                ++fileNamePtr;
                        }
                }

        }
	retVal = 1;

filenamedone:
	return retVal;
}

int getProcessLabel(unsigned int *procLabel, unsigned short int procId)
{
	listNode *tempNode;
	procAttr *tmpProcAttr;

	read_lock(pidListLock);
        if((tempNode = getListKey(pidListHead, procId)) == NULL)
	{
		read_unlock(pidListLock);
                return 0;
	}
        tmpProcAttr = (procAttr *)tempNode->data;
        *procLabel = tmpProcAttr->label;
	read_unlock(pidListLock);
	return 1;
}

//
// we're going to try a slower getFileLabel that handles recusive directories better
// 
/*int getFileLabel(const char *filename, unsigned int checkLabel, unsigned int *fileLabel)
{
        dlistNode *fileTmpNode = fileListHead;
	listNode *tempNode;
	fileAttr *tmpFileAttr;
	unsigned int tmpFileKey;
	int retVal = 0;

        // get the key setup 4 bytes of the real file name
        memset(&tmpFileKey, 0, 4);
        strncpy((char *)&tmpFileKey, filename, 4);

        while(fileTmpNode != NULL)
        {
                fileTmpNode = getDlistKey(fileTmpNode, tmpFileKey);
		if(fileTmpNode == NULL)
			goto getFileLabelReturn;
		tmpFileAttr = (fileAttr *)(fileTmpNode->data);
                if(!strncmp(filename, tmpFileAttr->filename, 1024))
                {
                        tmpFileAttr = (fileAttr *)(fileTmpNode->data);
                        // we've got a match!!  now we need to find the label
                        tempNode = getListMaskKey(tmpFileAttr->labelHead, checkLabel, LABEL_MASK);
                        if (tempNode != NULL)
                        {
				// we've got a match!
				*fileLabel = (unsigned int)(tempNode->key);
				retVal = 1;
				goto getFileLabelReturn;
			}
		}
		fileTmpNode = fileTmpNode->next;
	}

getFileLabelReturn:
	return retVal;
}*/

int fileStrncmp(const char *filename, const char *protfile, unsigned int numChar)
{
	char lastProtChar = 0;
	int matchNum = 0;

	while(matchNum < numChar)
	{
		// if we reach the end of filename
		if(*filename == 0)
		{
			// and its not also the end of protfile
			if(*protfile != 0)
			{
				// and we're not matching a dir
				if(*protfile == '/')
				{
					++protfile;
					if(*protfile != 0)
						// we don't have a match
						matchNum = -1;
				}
				else
					matchNum = -1;
			}
			break;
		}
		// if we reach the end of protfile
		if(*protfile == 0)
		{
			// and the last matched char was not a '/'
			if(lastProtChar != '/')
				// we don't have a match
				matchNum = -1;
			// else we have a partial match
			break;
		}
		// if the current char is different
		if(*filename != *protfile)
		{
			// we don't have a match
			matchNum = -1;
			break;
		}
		lastProtChar = *protfile;
		++filename;
		++protfile;
		++matchNum;
	}

	return matchNum;
}

int getFileLabel(const char *filename, unsigned int checkLabel, unsigned int *fileLabel)
{
        dlistNode *fileTmpNode;
	listNode *tempNode;
	fileAttr *tmpFileAttr;
	int retVal = 0;
	int bigMatch = 0, currentMatch = 0;

	read_lock(&fileListLock);
	fileTmpNode = fileListHead;
        while(fileTmpNode != NULL)
        {
		tmpFileAttr = (fileAttr *)(fileTmpNode->data);
                if((currentMatch = fileStrncmp(filename, tmpFileAttr->filename, 1024)) > 0)
                {
                        // we've got a match!!  now we need to find the label
                        tempNode = getListMaskKey(tmpFileAttr->labelHead, checkLabel, LABEL_MASK);
                        if (tempNode != NULL)
                        {
				// we've got a match!
				if(currentMatch > bigMatch)
				{
					// return OK
					retVal = 1;
					bigMatch = currentMatch;

					if(strlen(filename) == currentMatch)
					{
						// perfect match
						*fileLabel = (unsigned int)(tempNode->key);
						break;
					}
					else if((unsigned int)(tempNode->key) & LABEL_RECURSE)
						*fileLabel = (unsigned int)(tempNode->key);
				}
			}
		}
		fileTmpNode = fileTmpNode->next;
	}
	read_unlock(&fileListLock);

	return retVal;
}
