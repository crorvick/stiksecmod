/*
Stik's Security Module
module.c - main module source
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

#define MODULE
#define __KERNEL__

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <sys/syscall.h>
#include <asm/ptrace.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
// for sockaddr_in
#include <linux/in.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/sysctl.h>
#include <linux/utime.h>
#include <linux/sockios.h>
#include <linux/quota.h>
#include <linux/compatmac.h>
#include <linux/sched.h>
//#include <linux/xqm.h>
#include <asm/ptrace.h>
#include <asm/errno.h>

#include "global.c"
#include "syscalls.c"
#include "util.c"

#ifndef WESTSIDES_LIST_C
#include "list.c"
#endif

#include "dlist.c"

#ifndef WESTSIDES_PROCESS
#include "process.h"
#endif

#ifndef WESTSIDES_PRIVILEGE
#include "privilege.h"
#endif

#ifndef WESTSIDES_FILE
#include "file.h"
#endif

#ifndef WESTSIDES_LABEL
#include "label.h"
#endif

// we rip this off for sys_socketcall
#define AL(x) ((x) * sizeof(unsigned long))
static unsigned char nargs[18]={AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
				AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
				AL(6),AL(2),AL(5),AL(5),AL(3),AL(3)};
#undef AL

// GPL this sucker
MODULE_LICENSE("GPL");

// syscalls
long *my_sys_call_table;
long orig_sys_call_table[NR_syscalls];
long (*sec_sys_call_table[NR_syscalls])();

// We don't yet support labeled IPC - which could leave a system open to some memory based information attacks

int new_bind(int fd, struct sockaddr *umyaddr, int addrlen);
int new_connect(int fd, struct sockaddr *uservaddr, int addrlen);
int new_sendto(int fd, void * buff, size_t len, unsigned flags, struct sockaddr *addr, int addr_len);

long secDefault(void)
{
	return 0;
}

long new_socketcall(int call, unsigned long *args)
{
	unsigned long a[6];
	unsigned long a0,a1;
	int err;

	if(call<1||call>SYS_RECVMSG)
		return -EINVAL;

	/* copy_from_user should be SMP safe. */
	if (copy_from_user(a, args, nargs[call]))
		return -EFAULT;
		
	a0=a[0];
	a1=a[1];
	
	switch(call) 
	{
		//case SYS_SOCKET:
			//err = sys_socket(a0,a1,a[2]);
			//break;
		case SYS_BIND:
			err = new_bind(a0,(struct sockaddr *)a1, a[2]);
			break;
		case SYS_CONNECT:
			err = new_connect(a0, (struct sockaddr *)a1, a[2]);
			break;
		//case SYS_LISTEN:
			//err = sys_listen(a0,a1);
			//break;
		//case SYS_ACCEPT:
			//err = sys_accept(a0,(struct sockaddr *)a1, (int *)a[2]);
			//break;
		//case SYS_GETSOCKNAME:
			//err = sys_getsockname(a0,(struct sockaddr *)a1, (int *)a[2]);
			//break;
		//case SYS_GETPEERNAME:
			//err = sys_getpeername(a0, (struct sockaddr *)a1, (int *)a[2]);
			//break;
		//case SYS_SOCKETPAIR:
			//err = sys_socketpair(a0,a1, a[2], (int *)a[3]);
			//break;
		//case SYS_SEND:
			//err = sys_send(a0, (void *)a1, a[2], a[3]);
			//break;
		case SYS_SENDTO:
			err = new_sendto(a0,(void *)a1, a[2], a[3],
					 (struct sockaddr *)a[4], a[5]);
			break;
		//case SYS_RECV:
			//err = sys_recv(a0, (void *)a1, a[2], a[3]);
			//break;
		//case SYS_RECVFROM:
			//err = sys_recvfrom(a0, (void *)a1, a[2], a[3],
					   //(struct sockaddr *)a[4], (int *)a[5]);
			//break;
		//case SYS_SHUTDOWN:
			//err = sys_shutdown(a0,a1);
			//break;
		//case SYS_SETSOCKOPT:
			//err = sys_setsockopt(a0, a1, a[2], (char *)a[3], a[4]);
			//break;
		//case SYS_GETSOCKOPT:
			//err = sys_getsockopt(a0, a1, a[2], (char *)a[3], (int *)a[4]);
			//break;
		//case SYS_SENDMSG:
			//err = sys_sendmsg(a0, (struct msghdr *) a1, a[2]);
			//break;
		//case SYS_RECVMSG:
			//err = sys_recvmsg(a0, (struct msghdr *) a1, a[2]);
			//break;
		default:
			err = 1;
			break;
	}

	if(err < 1)
		return -EACCES;

	return 0;
}

long new_kill(int pid, int sig)
{
	unsigned int myLabel, theirLabel;
	int pidGroup;
	struct task_struct *taskStruct;

	// can only send signals to same label unless privilege
	if(getProcessLabel(&myLabel, current->pid) < 1)
		// I've got no protection
		goto returnKill;
	if(checkPrivilege(PRIVILEGE_SIGNAL) > 0)
		goto returnKill;
	if(pid == 0)
		// You can signal yourself all day
		goto returnKill;
	if(pid > 0)
	{
		if(getProcessLabel(&theirLabel, pid) < 1)
			// They have no protection
			return -EPERM;
		if((myLabel & LABEL_MASK) == (theirLabel & LABEL_MASK))
			goto returnKill;
		return -EPERM;
	}
	if(pid < -2)
	{
		// signalling a pgroup... what a fucker
		pidGroup = pid * -1;
		read_lock(&tasklist_lock);
		for_each_task(taskStruct)
		{
			if(taskStruct->pgrp == pidGroup)
			{
				if(getProcessLabel(&theirLabel, taskStruct->pid) < 1)
				{
					// They have no protection
					read_unlock(&tasklist_lock);
					return -EPERM;
				}
				if((myLabel & LABEL_MASK) != (theirLabel & LABEL_MASK))
				{
					read_unlock(&tasklist_lock);
					return -EPERM;
				}
			}
		}
		read_unlock(&tasklist_lock);
		goto returnKill;
	}
	// can't signal everybody, jackass
	return -EPERM;

returnKill:
	return 0;
}
	
long privilegeNICE(void)
{
        if(checkPrivilege(PRIVILEGE_NICE) < 1)
        {
                return -EPERM;
        }
	return 0;
}

long privilegeNAME(void)
{
        if(checkPrivilege(PRIVILEGE_NAME) < 1)
        {
                return -EPERM;
        }
	return 0;
}
	
long privilegeSETID(void)
{
        if(checkPrivilege(PRIVILEGE_SETID) < 1)
        {
                return -EPERM;
        }
	return 0;
}

long new_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	// only some ioctls are privileged - hopefully the cmds are reserverd
	// SIOCSIFFLAGS SIOCSIFMTU SIOCSIFHWADDR SIOCSIFHWBROADCAST SIOCSIFMAP SIOCSIFNAME 
	if((cmd & SIOCSIFFLAGS) || (cmd & SIOCSIFMTU) || (cmd & SIOCSIFHWADDR) || (cmd & SIOCSIFHWBROADCAST) || (cmd & SIOCSIFMAP) || (cmd & SIOCSIFNAME))
	{
		// privileged ioctl
        	if(checkPrivilege(PRIVILEGE_IOCTL) < 1)
        	{
                	return -EPERM;
        	}
	}
	return 0;
}

long privilegeMOUNT(void)
{
        if(checkPrivilege(PRIVILEGE_MOUNT) < 1)
        {
                return -EPERM;
        }
	return 0;
}

long privilegeNFSCTL(void)
{
        if(checkPrivilege(PRIVILEGE_NFSCTL) < 1)
        {
                return -EPERM;
        }
	return 0;
}

// can't hook the bind syscall directly 
// >0 means good to go
int new_bind(int fd, struct sockaddr *umyaddr, int addrlen)
{
	unsigned int procLabel;

	if(getProcessLabel(&procLabel, current->pid) < 1)
		goto doBind;

	if(localNetworkAccess(procLabel, umyaddr) < 1)
		return 0;

doBind:
	return 1;
}

long privilegeRLIMIT(void)
{
        if(checkPrivilege(PRIVILEGE_RLIMIT) < 1)
        {
                return -EPERM;
        }
	return 0;
}

long new_acct(const char *name)
{
	// we need privilege and write permission on the file
	unsigned int processLabel, fileLabel;
	char realFilename[1024];

        if(checkPrivilege(PRIVILEGE_ACCT) < 1)
        {
                return -EPERM;
        }

	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto acctReturn;

        // lets resolve the real path of oldname
	if(realFileName(name, realFilename, 1024) < 1)
		goto acctReturn;

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return -EPERM;

acctReturn:
	return 0;
}

long secCreateFile(const char * pathname)
{
	// we need write permission on the directory to create a directory
	unsigned int processLabel, fileLabel;
	char realFilename[1024], *realFilePtr;
	
	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto mkdirReturn;

        // lets resolve the real path of oldname
	if(realFileName(pathname, realFilename, 1024) < 1)
		goto mkdirReturn;

	// we need to check write against the directory the file is in
	// so we get the directory by modifying realFilename
	realFilePtr = realFilename;
	while(*realFilePtr != 0)
		++realFilePtr;
	while(*realFilePtr != '/')
	{
		*realFilePtr = 0;
		--realFilePtr;
	}

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return -EACCES;

mkdirReturn:
	return 0;
}

long privilegeSYSLOG(void)
{
        if(checkPrivilege(PRIVILEGE_SYSLOG) < 1)
        {
                return -EPERM;
        }
	return 0;
}

long privilegeSWAP(void)
{
        if(checkPrivilege(PRIVILEGE_SWAP) < 1)
        {
                return -EPERM;
        }
	return 0;
}

long privilegeFILESYSTEM(const char * filename)
{
        if(checkPrivilege(PRIVILEGE_FILESYSTEM) < 1)
        {
                return -EPERM;
        }
	return 0;
}

long secExecFile(const char * filename)
{
	// we need search on the directory
	unsigned int processLabel, fileLabel;
	char realFilename[1024];
	
	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto chdirReturn;

        // lets resolve the real path of oldname
	if(realFileName(filename, realFilename, 1024) < 1)
		goto chdirReturn;

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_EXEC) < 1)
		return -EACCES;

chdirReturn:
	return 0;
}

long secWriteFile(const char * path)
{
	// we need write on the file
	unsigned int processLabel, fileLabel;
	char realFilename[1024];
	
	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto truncate64Return;

        // lets resolve the real path of oldname
	if(realFileName(path, realFilename, 1024) < 1)
		goto truncate64Return;

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return -EACCES;

truncate64Return:
	return 0;
}

long new_uselib(const char * library)
{
	// we need read and exec on the library
	unsigned int processLabel, fileLabel;
	char realFilename[1024];
	
	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto uselibReturn;

        // lets resolve the real path of oldname
	if(realFileName(library, realFilename, 1024) < 1)
		goto uselibReturn;

	// now that we've resolved the real pathname, we need to check if we have delete on the file,
	// then write on the directory its in
	// get the filelabel
	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_READ) < 1)
		return -EACCES;

	if(fileLabelAccess(processLabel, fileLabel, LABEL_EXEC) < 1)
		return -EACCES;

uselibReturn:
	 return 0;
}

long new_rename(const char * oldname, const char * newname)
{
	// we need to have delete to oldname and create for newname and if newname exists, delete for newname
	// STIK - should we copy the attributes over automatically?
	unsigned int processLabel, fileLabel;
	char realFilename[1024], *realFilePtr;
	
	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto renameReturn;

        // lets resolve the real path of oldname
	if(realFileName(oldname, realFilename, 1024) < 1)
		goto renameReturn1;

	// now that we've resolved the real pathname, we need to check if we have delete on the file,
	// then write on the directory its in
	// get the filelabel
	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_DELETE) < 1)
		return -EACCES;

	// we need to check write against the directory the file is in
	// so we get the directory by modifying realFilename
	realFilePtr = realFilename;
	while(*realFilePtr != 0)
		++realFilePtr;
	while(*realFilePtr != '/')
	{
		*realFilePtr = 0;
		--realFilePtr;
	}
renameReturn1:

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return -EACCES;

        // lets resolve the real path of newname
	if(realFileName(oldname, realFilename, 1024) < 1)
		goto renameReturn;

	// now that we've resolved the real pathname, we need to check if we have delete on the file,
	// then write on the directory its in
	// get the filelabel
	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_DELETE) < 1)
		return -EACCES;

	// we need to check write against the directory the file is in
	// so we get the directory by modifying realFilename
	realFilePtr = realFilename;
	while(*realFilePtr != 0)
		++realFilePtr;
	while(*realFilePtr != '/')
	{
		*realFilePtr = 0;
		--realFilePtr;
	}

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return -EACCES;

renameReturn:
	return 0;
}

//
// STIK - the fork series work differently
// 	- so we need to handle saving their original file pointers
//	- and calling these functions differently
//	
int (*old_fork)(struct pt_regs regs);
int new_fork(struct pt_regs regs)
{
	int newPid;
	// we really should build over the basic types so we can call things like addProcess()
	listNode *pidNewNode;
	listNode *pidTempNode;
	procAttr *newProcAttr; 
	procAttr *tempProcAttr; 

	// hmm wonder if there is a race condition caused by doing fork first
	// i guess no, esp. if userspace is waiting on a return from this syscall
	newPid =(*old_fork)(regs);

	// see if this is a protected process, if so, mark the process being forked
	write_lock(&pidListLock);
	if((pidTempNode = getListKey(pidListHead,current->pid)) != NULL)
	{
		pidNewNode = (listNode *)kmalloc(sizeof(listNode), GFP_KERNEL);
		memset(pidNewNode, 0, sizeof(listNode));
		newProcAttr = (procAttr *)kmalloc(sizeof(procAttr), GFP_KERNEL);
		memset(newProcAttr, 0, sizeof(procAttr));
		tempProcAttr = (procAttr *)pidTempNode->data;

		pidNewNode->key = newPid;
		newProcAttr->label = tempProcAttr->label;
		newProcAttr->privileges = tempProcAttr->privileges;
		pidNewNode->data = (void *)newProcAttr;

		pidListHead = listInsert(pidListHead, pidNewNode);

	}
	write_unlock(&pidListLock);

	return newPid;
}

int (*old_clone)(struct pt_regs regs);
int new_clone(struct pt_regs regs)
{
	int newPid;
	// we really should build over the basic types so we can call things like addProcess()
	listNode *pidNewNode;
	listNode *pidTempNode;
	procAttr *newProcAttr; 
	procAttr *tempProcAttr; 

	// hmm wonder if there is a race condition caused by doing fork first
	// i guess no, esp if userspace is waiting on a return from this syscall
	newPid =(*old_clone)(regs);

	// see if this is a protected process, if so, mark the process being forked
	write_lock(&pidListLock);
	if((pidTempNode = getListKey(pidListHead,current->pid)) != NULL)
	{
		pidNewNode = (listNode *)kmalloc(sizeof(listNode), GFP_KERNEL);
		memset(pidNewNode, 0, sizeof(listNode));
		newProcAttr = (procAttr *)kmalloc(sizeof(procAttr), GFP_KERNEL);
		memset(newProcAttr, 0, sizeof(procAttr));
		tempProcAttr = (procAttr *)pidTempNode->data;

		pidNewNode->key = newPid;
		newProcAttr->label = tempProcAttr->label;
		newProcAttr->privileges = tempProcAttr->privileges;
		pidNewNode->data = (void *)newProcAttr;

		pidListHead = listInsert(pidListHead, pidNewNode);

	}
	write_unlock(&pidListLock);
	return newPid;
}

int (*old_vfork)(struct pt_regs regs);
int new_vfork(struct pt_regs regs)
{
	int newPid;
	// we really should build over the basic types so we can call things like addProcess()
	listNode *pidNewNode;
	listNode *pidTempNode;
	procAttr *newProcAttr; 
	procAttr *tempProcAttr; 

	// hmm wonder if there is a race condition caused by doing fork first
	// i guess no, esp if userspace is waiting on a return from this syscall
	newPid = (*old_vfork)(regs);

	// see if this is a protected process, if so, mark the process being forked
	write_lock(&pidListLock);
	if((pidTempNode = getListKey(pidListHead,current->pid)) != NULL)
	{
		pidNewNode = (listNode *)kmalloc(sizeof(listNode), GFP_KERNEL);
		memset(pidNewNode, 0, sizeof(listNode));
		newProcAttr = (procAttr *)kmalloc(sizeof(procAttr), GFP_KERNEL);
		memset(newProcAttr, 0, sizeof(procAttr));
		tempProcAttr = (procAttr *)pidTempNode->data;

		pidNewNode->key = newPid;
		newProcAttr->label = tempProcAttr->label;
		newProcAttr->privileges = tempProcAttr->privileges;
		pidNewNode->data = (void *)newProcAttr;

		pidListHead = listInsert(pidListHead, pidNewNode);

	}
	write_unlock(&pidListLock);
	return newPid;
}

long new_mknod(const char * filename, int mode, dev_t dev)
{
	unsigned int processLabel, fileLabel;
	char realFilename[1024], *tmpFilename;
	// STIK - should we force process attr's on the nod?

        if(checkPrivilege(PRIVILEGE_MKNOD) < 1)
        {
                return -EPERM;
        }
	
	// we need to make sure we have write access to the directory that this file is in
	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto mknodReturn;

	if(realFileName(filename, realFilename, 1024) < 1)
		goto mknodReturn;

	// turn realFilename into the directory name
	tmpFilename = realFilename;
	while(*tmpFilename != 0) 
		++tmpFilename;
	while(*tmpFilename != '/')
	{
		*tmpFilename = 0;
		--tmpFilename;
	}

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	
	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return -EACCES;

mknodReturn:
	return 0;
}
	
long new_quotactl(int cmd, const char *special, int id, caddr_t addr)
{
	// we only privilege restrict some quota operations
	int cmds = cmd >> SUBCMDSHIFT;
	if(cmds & (Q_QUOTAON | Q_QUOTAOFF | Q_SETQUOTA | Q_SETQLIM | Q_SETUSE ))
	{
		if(checkPrivilege(PRIVILEGE_FSQUOTA) < 1)
        	{
                	return -EPERM;
        	}
	}
	return 0;
}

// ptrace should definitely be restricted by label - i'm sure someone will debate whether it needs to be restricted by privilege as well
long new_ptrace(long request, long pid, long addr, long data)
{
	unsigned int currentLabel, traceLabel;
	if(getProcessLabel(&currentLabel, current->pid) < 1)
		// we are unprotected - go for it
		goto ptraceReturn;
	if(getProcessLabel(&traceLabel, (short int)pid) < 1)
		// protected tracing unprotected - no way
		return -EPERM;
	if(currentLabel != traceLabel)
		//different labels - no way
		return -EPERM;
ptraceReturn:
	return 0;
}

asmlinkage int new_execve(struct pt_regs regs)
{
	// hanlde DOE and check EXEC on the file
	listNode *tmpListNode;
	procAttr *tmpProcAttr;
	unsigned int tmpDOE;
	int retVal;
	char * filename;
	char realFilename[1024];
	unsigned int processLabel, fileLabel;

	if(getProcessLabel(&processLabel, current->pid) < 1)
	{
		read_unlock(&pidListLock);
		goto execve_return;
	}

        // lets resolve the real path
	if(realFileName((char *)regs.ebx, realFilename, 1024) < 1)
		goto execPrivs;

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);

	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_EXEC) < 1)
		return -EACCES;

	
execPrivs:
	write_lock(&pidListLock);
	if((tmpListNode = getListKey(pidListHead, current->pid)) == NULL)
	{
		write_unlock(&pidListLock);
		goto execve_return;
	}
	tmpProcAttr = (procAttr *)(tmpListNode->data);

	tmpDOE = tmpProcAttr->privileges & DOE_MASK;
	// clear the DOE flags
	tmpProcAttr->privileges -= tmpDOE;
	// clear the privilegs, and only the privileges that are set, so we don't mess up what DOU might have done
	tmpDOE = tmpDOE >> 1;   // whoa little endian specific
	tmpDOE = tmpDOE - (tmpProcAttr->privileges & tmpDOE);
	tmpProcAttr->privileges += tmpDOE;
	write_unlock(&pidListLock);

execve_return:
	// I don't like this solution, but these seems to be how other people did it
	filename = getname((char *) regs.ebx);
	retVal = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;
	retVal = do_execve(filename, (char **) regs.ecx, (char **) regs.edx, &regs);
	if (retVal == 0)
		current->ptrace &= ~PT_DTRACE;
	putname(filename);
out:
	return retVal;
}
	

// hope these io perm bit calls don't break anything :)
long privilegeRAWIO(void)
{
        if(checkPrivilege(PRIVILEGE_RAWIO) < 1)
        {
                return -EPERM;
        }
	return 0;
}

long privilegeREBOOT(void)
{
        if(checkPrivilege(PRIVILEGE_REBOOT) < 1)
        {
                return -EPERM;
        }
        return 0;
}

long new_adjtimex(struct timex *txc_p)
{
        if(txc_p->modes && (checkPrivilege(PRIVILEGE_TIME) < 1))
        {
                return -EPERM;
        }
	return 0;
}
	
long privilegeTIME(void)
{
        if(checkPrivilege(PRIVILEGE_TIME) < 1)
        {
                return -EPERM;
        }
	return 0;
}

long privilegeMODULE(const char *name)
{
	// This will prevent the module from being removed
	if(!strncmp(name, "stiksec", 7))
		return -EPERM;

	if(checkPrivilege(PRIVILEGE_MODULE) < 1)
	{
		return -EPERM;
	}

	return 0;
}
	
long new_mount(char * dev_name, char * dir_name, char * type, unsigned long flags, void * data)
{
	if(checkPrivilege(PRIVILEGE_MOUNT) < 1)
	{
		return -EPERM;
	}
	// we also want to check filesystem rights on a mount

	return 0;
}

long new_umount(char * name, int flags)
{
	if(checkPrivilege(PRIVILEGE_MOUNT) < 1)
	{
		return -EPERM;
	}
	// we also want to check filesystem rights on a umount

	return 0;
}

long new_exit(int error_code)
{
	unsigned int tempPid = current->pid;
	listNode *tmpListNode;
	procAttr *tmpProcAttr;
	
	// This handles clean program terminations
	// We would like to wait until exit to take the pid off the list to avoid race contiditons with threads, but we can't bummer for us
	// we have to handle cleanup because util does not;
	write_lock(&pidListLock);
	if((tmpListNode = getListKey(pidListHead,tempPid)) != NULL)
	{
		tmpProcAttr = (procAttr *)tmpListNode->data;
		kfree(tmpProcAttr);
		pidListHead = listDelete(pidListHead, tempPid);
		kfree(tmpListNode);
	}
	write_unlock(&pidListLock);

	//retVal = (*old_exit)(error_code);
	
	return 0;
}

long new_open(const char * filename, int flags, int mode)
{
	unsigned int processLabel, fileLabel;
	char realFilename[1024];

	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto openReturn;

	// do we need to check for symlinks - probably
	if(realFileName(filename, realFilename, 1024) < 1)
		goto openReturn;
	
	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
                                
	if((flags & O_ACCMODE) == O_RDONLY)
	{
		if(fileLabelAccess(processLabel, fileLabel, LABEL_READ) < 1)
			return -EACCES;
		goto openReturn;
	}
	if((flags & O_ACCMODE) == O_WRONLY)
	{
		if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
			return -EACCES;
		goto openReturn;
	}
	if((flags & O_ACCMODE) == O_RDWR)
	{
		// we have to check both read and write
		if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) + fileLabelAccess(processLabel, fileLabel, LABEL_READ) < 2)
			return -EACCES;
		goto openReturn;
	}

openReturn:
	return 0;
}

int new_sendto(int fd, void * buff, size_t len, unsigned flags, struct sockaddr *addr, int addr_len)
{
	unsigned int procLabel;

	if(getProcessLabel(&procLabel, current->pid) < 1)
		goto doSendto;

	if(remoteNetworkAccess(procLabel, addr) < 1)
		return 0;

doSendto:
	return 1;
}

int new_connect(int fd, struct sockaddr *uservaddr, int addrlen)
{
	unsigned int procLabel;

	if(getProcessLabel(&procLabel, current->pid) < 1)
		goto doConnect;

	if(remoteNetworkAccess(procLabel, uservaddr) < 1)
		return 0;

doConnect:
	return 1;
}

long new_symlink(const char * oldname, const char * newname)
{
        // if we create a hard link to a file, we should replicate the security on it
        dlistNode *tmpFileNode = fileListHead;
        unsigned int tmpKey;
        char newFilename[1024], oldFilename[1024];
        listNode *tmpListNode, *newListNode;
        fileAttr *tmpFileAttr, *newFileAttr;
	char *realFilePtr, realFilename[1024];
	unsigned int processLabel, fileLabel;

        // lets resolve the real path of newname
        if(realFileName(newname, newFilename, 1024) < 1)
                goto symlinkReturn;

        // now we resolve oldname
        if(realFileName(oldname, oldFilename, 1024) < 1)
                goto symlinkReturn;

	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto symlinkLabelCopy;

	// check for write on the directory
	strncpy(realFilename, oldFilename, 1024);
	realFilePtr = realFilename;
	while(*realFilePtr != 0)
		++realFilePtr;
	while(*realFilePtr != '/')
	{
		*realFilePtr = 0;
		--realFilePtr;
	}

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);

	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return -EACCES;

symlinkLabelCopy:
        // search on oldname to see if we have attributes already set
        memset(&tmpKey, 0, 4);
        strncpy((char *)&tmpKey, oldFilename, 4);

        // can we cut this out some?  we don't need to yet
	write_lock(&fileListLock);
        while(tmpFileNode != NULL)
        {
                tmpFileNode = getDlistKey(tmpFileNode, tmpKey);
                tmpFileAttr = (fileAttr *)tmpFileNode->data;
                if(!strncmp(oldFilename, tmpFileAttr->filename, 1024))
                {
                        // this is the right file, let's setup a new node & copy the security info
                        tmpFileNode = (dlistNode *)kmalloc(sizeof(dlistNode), GFP_KERNEL);
			memset(tmpFileNode, 0, sizeof(dlistNode));

                        memcpy(&tmpKey, newFilename, 4);
                        tmpFileNode->key = tmpKey;

                        if(tmpFileAttr != NULL)
                        {
                                newFileAttr = (fileAttr *)kmalloc(sizeof(fileAttr), GFP_KERNEL);
				memset(newFileAttr, 0, sizeof(fileAttr));
                                memcpy(newFileAttr->filename, newFilename, 1024);

                                tmpListNode = tmpFileAttr->labelHead;
                                while (tmpListNode != NULL)
                                {
                                        newListNode = (listNode *)kmalloc(sizeof(listNode), GFP_KERNEL);
					memset(newListNode, 0, sizeof(listNode));
                                        newListNode->key = tmpListNode->key;
                                        newFileAttr->labelHead = listInsert(newFileAttr->labelHead, newListNode);
                                }
                        }
                        dlistInsertBefore(&fileListHead, &fileListTail, fileListHead, tmpFileNode);
			write_unlock(&fileListLock);
                        goto symlinkReturn;
                }
        }
	write_unlock(&fileListLock);

symlinkReturn:
        return 0;
}

long new_link(const char * oldname, const char * newname)
{
	// if we create a hard link to a file, we should replicate the security on it
	// STIK - we need to check write in the directory we are creating the file as well
	dlistNode *tmpFileNode = fileListHead;
	unsigned int tmpKey;
	char newFilename[1024], oldFilename[1024];
	listNode *tmpListNode, *newListNode;
	fileAttr *tmpFileAttr, *newFileAttr;
	unsigned int processLabel, fileLabel;
	char *realFilePtr, realFilename[1024];

	// lets resolve the real path of newname
	if(realFileName(newname, newFilename, 1024) < 1)
		goto linkReturn;

	// now we resolve oldname
	if(realFileName(oldname, oldFilename, 1024) < 1)
		goto linkReturn;

	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto linkLabelCopy;

	// check for write on the directory
	strncpy(realFilename, oldFilename, 1024);
	realFilePtr = realFilename;
	while(*realFilePtr != 0)
		++realFilePtr;
	while(*realFilePtr != '/')
	{
		*realFilePtr = 0;
		--realFilePtr;
	}

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);

	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return -EACCES;

linkLabelCopy:
	// search on oldname to see if we have attributes already set
	memset(&tmpKey, 0, 4);
	strncpy((char *)&tmpKey, oldFilename, 4);
	
	// can we cut this out some?  we don't need to yet
	write_lock(&fileListLock);
	while(tmpFileNode != NULL)
	{
		tmpFileNode = getDlistKey(tmpFileNode, tmpKey);
		tmpFileAttr = (fileAttr *)(tmpFileNode->data);
                if(!strncmp(oldFilename, tmpFileAttr->filename, 1024))
                {
			// this is the right file, let's setup a new node & copy the security info
			tmpFileNode = (dlistNode *)kmalloc(sizeof(dlistNode), GFP_KERNEL);
			memset(tmpFileNode, 0, sizeof(dlistNode));

			memcpy(&tmpKey, newFilename, 4);
			tmpFileNode->key = tmpKey;
			
			if(tmpFileAttr != NULL)
			{
				newFileAttr = (fileAttr *)kmalloc(sizeof(fileAttr), GFP_KERNEL);
				memset(newFileAttr, 0, sizeof(fileAttr));
				memcpy(newFileAttr->filename, newFilename, 1024);
	
				tmpListNode = tmpFileAttr->labelHead;
				while (tmpListNode != NULL)
				{
					newListNode = (listNode *)kmalloc(sizeof(listNode), GFP_KERNEL);
					memset(newListNode, 0, sizeof(listNode));
					newListNode->key = tmpListNode->key;
					newFileAttr->labelHead = listInsert(newFileAttr->labelHead, newListNode);
				}
			}
			dlistInsertBefore(&fileListHead, &fileListTail, fileListHead, tmpFileNode);
			write_unlock(&fileListLock);
			goto linkReturn;
		}
	}
	write_unlock(&fileListLock);
linkReturn:

	return 0;
}

long secDeleteFile(const char * pathname)
{
        char realFilename[1024], *realFilePtr;
	unsigned int processLabel, fileLabel;

	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto unlinkReturn;

        // lets resolve the real path of pathname
	if(realFileName(pathname, realFilename, 1024) < 1)
		goto unlinkReturn;

	// now that we've resolve the real pathname, we need to check if we have delete on the file,
	// then write on the directory its in
	// get the filelabel
	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_DELETE) < 1)
		return -EACCES;

	// we need to check write against the directory the file is in
	// so we get the directory by modifying realFilename
	realFilePtr = realFilename;
	while(*realFilePtr != 0)
		++realFilePtr;
	while(*realFilePtr != '/')
	{
		*realFilePtr = 0;
		--realFilePtr;
	}

	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return -EACCES;

unlinkReturn:
	return 0;
}


// driver functions
static int driverOpen(struct inode *i, struct file *f)
{
	return 0;
}

static int driverIoctl(struct inode *i, struct file *f, unsigned int optionNum, unsigned long dataPtr)
{
	// this is ugly, but we'll move it around soon enough
	listNode *pidNewNode;
	procAttr *newProcAttr;
	procPass *tempProcPass;
	dlistNode *fileTmpNode;
	dlistNode *fileTmpNode2 = NULL;
	listNode *tmpListNode;
	listNode *netListNode;
	listNode *tmpListNode2 = NULL;
	listNode *netListNode2 = NULL;
	fileAttr *newFileAttr;
	fileAttr *tmpFileAttr;
	passFileAttr *pFileAttr;
	netAttr *newNetAttr;
	netPassAttr *pNetAttr;

	char *realFilename;
	char *strPtr;
	unsigned int tmpVal;
	unsigned int tmpVal2;

	// protected processes shouldn't have access to the module
	// although we may want them to have access to their own labels
	if(getListKey(pidListHead, current->pid) != NULL)
		return -1;

	switch(optionNum) 
	{
		case 0:
		// set process attributes

		pidNewNode = (listNode *)kmalloc(sizeof(listNode), GFP_KERNEL);
		memset(pidNewNode, 0, sizeof(listNode));
		newProcAttr = (procAttr *)kmalloc(sizeof(procAttr), GFP_KERNEL);
		memset(newProcAttr, 0, sizeof(procAttr));

		// hopefully we don't have to copy this info to use it
		tempProcPass = (procPass *)dataPtr;


		// our key is the pid
		pidNewNode->key = tempProcPass->pid;
		newProcAttr->label = tempProcPass->label;
		newProcAttr->privileges = tempProcPass->privileges;
		pidNewNode->data = (void *)newProcAttr;

		write_lock(&pidListLock);
		pidListHead = listInsert(pidListHead, pidNewNode);
		write_unlock(&pidListLock);
		break;
		;;
		
		case 1:
		// set file attributes
		pFileAttr = (passFileAttr *)dataPtr;

		realFilename = (char *)kmalloc(1024, GFP_KERNEL);
		memset(realFilename, 0, 1024);
		realFileName(pFileAttr->filename, realFilename, 1024);

		// the key is the first 4 bytes of the filename
		memcpy(&tmpVal, realFilename, 4);

		write_lock(&fileListLock);

		// lets see if we have a file node with the same filename
		fileTmpNode = fileListHead;
		while(fileTmpNode != NULL)
		{
			fileTmpNode = getDlistKey(fileTmpNode, tmpVal);
			if (fileTmpNode != NULL)		
			{
				tmpFileAttr = (fileAttr *)(fileTmpNode->data);
				if(!strncmp(realFilename, tmpFileAttr->filename, 1024))
				{
					// we've got a match!!  now we need to see if the label is in there & replace it if so
					tmpListNode = getListMaskKey(tmpFileAttr->labelHead, pFileAttr->label, LABEL_MASK);
					if(tmpListNode == NULL)
					{
						// create a new node to hold the new label
						tmpListNode = (listNode *)kmalloc(sizeof(listNode), GFP_KERNEL);
						memset(tmpListNode, 0, sizeof(listNode));
						tmpListNode->key = pFileAttr->label;
						tmpListNode->next = NULL;
						tmpFileAttr->labelHead = listInsert(tmpFileAttr->labelHead, tmpListNode);
					}
					else			
					{
						// we have this label defined, replace it
						tmpListNode->key = pFileAttr->label;
					}
					kfree(realFilename);
					write_unlock(&fileListLock);
					return 0;
				}
			// That wasn't the right node, but we can keep looking
			// if(fileTmpNode->next != NULL)
				fileTmpNode = fileTmpNode->next;
			}
		}
		
		// this is a new file we are setting a label on
		fileTmpNode = (dlistNode *)kmalloc(sizeof(dlistNode), GFP_KERNEL);
		memset(fileTmpNode, 0, sizeof(dlistNode));
		newFileAttr = (fileAttr *)kmalloc(sizeof(fileAttr), GFP_KERNEL);
		memset(newFileAttr, 0, sizeof(fileAttr));

		// create a new node to hold the new label
		tmpListNode = (listNode *)kmalloc(sizeof(listNode), GFP_KERNEL);
		memset(tmpListNode, 0, sizeof(listNode));
		tmpListNode->key = pFileAttr->label;
		tmpListNode->next = NULL;
		newFileAttr->labelHead = listInsert(newFileAttr->labelHead, tmpListNode);
		
		// populate the rest of the file node
		memcpy(newFileAttr->filename, realFilename, 1024);
		fileTmpNode->data = (void *)newFileAttr;
		memcpy(&(fileTmpNode->key), realFilename, 4);

		fileTmpNode->next = NULL;
		fileTmpNode->prev = NULL;
		dlistInsertBefore(&fileListHead, &fileListTail, fileListHead, fileTmpNode);
		kfree(realFilename);

		write_unlock(&fileListLock);
		break;
		;;

		case 2:
		// set network restrictions
		pNetAttr = (netPassAttr *)dataPtr;

		write_lock(&netListLock);

		if((tmpListNode = getListKey(netListHead, pNetAttr->label)) == NULL)
		{
			// this label hasn't been defined yet
			tmpListNode = (listNode *)kmalloc(sizeof(listNode), GFP_KERNEL);
			memset(tmpListNode, 0, sizeof(listNode));
			tmpListNode->key = pNetAttr->label;
			tmpListNode->data = NULL;
			tmpListNode->next = NULL;
			netListHead = listInsert(netListHead, tmpListNode);
		}
		// now we insert the new network attr into the netAttr list
		newNetAttr = (netAttr *)kmalloc(sizeof(netAttr), GFP_KERNEL);
		memset(newNetAttr, 0, sizeof(netAttr));
		newNetAttr->laddr = pNetAttr->laddr;
		newNetAttr->lmask = pNetAttr->lmask;
		newNetAttr->lport = pNetAttr->lport;
		newNetAttr->lrange = pNetAttr->lrange;
		newNetAttr->raddr = pNetAttr->raddr;
		newNetAttr->rmask = pNetAttr->rmask;
		newNetAttr->rport = pNetAttr->rport;
		newNetAttr->rrange = pNetAttr->rrange;

		netListNode = (listNode *)kmalloc(sizeof(listNode), GFP_KERNEL);
		memset(netListNode, 0, sizeof(listNode));
		netListNode->data = (void *)newNetAttr;
		tmpListNode->data = (void *)listInsert((listNode *)(tmpListNode->data), netListNode);

		write_unlock(&netListLock);
		break;
		;;

		case 3:
		// dump the protected process list to the user
		read_lock(&pidListLock);

		tmpListNode = pidListHead;
		while(tmpListNode != NULL)
		{
			printk("WESTSIDES  pid: %d  ",tmpListNode->key);
			newProcAttr = (procAttr *)tmpListNode->data;
			printk("label: %d  priv: %d\n",newProcAttr->label,newProcAttr->privileges);
			tmpListNode = tmpListNode->next;
		}
		
		read_unlock(&pidListLock);
		break;
		;;

		case 4:
		// dump the protected file list to the user
		read_lock(&fileListLock);

		fileTmpNode = fileListHead;
		while (fileTmpNode != NULL)
		{
			printk("WSDS fileKey: %u\n",fileTmpNode->key);
			tmpFileAttr = (fileAttr *)fileTmpNode->data;
			printk("WSDS fileName: %s\n",tmpFileAttr->filename);
			tmpListNode = tmpFileAttr->labelHead;
			printk("WSDS filelabel: ");
			while(tmpListNode != NULL)
			{
				printk("%u  ",tmpListNode->key);
				tmpListNode = tmpListNode->next;
			}
			printk("\n");
			fileTmpNode = fileTmpNode->next;
		}		
		
		read_unlock(&fileListLock);
		break;
		;;
		
		case 5:
		// return the label and privileges for a pid to the user
		tempProcPass = (procPass *)dataPtr;
		
		read_lock(&pidListLock);

		tmpListNode = getListKey(pidListHead, tempProcPass->pid);
		if(tmpListNode == NULL)
			return -1;
		newProcAttr = (procAttr *)tmpListNode->data;
		tempProcPass = (procPass *)kmalloc(sizeof(procPass), GFP_KERNEL);
		memset(tempProcPass, 0, sizeof(procPass));
		tempProcPass->pid = tmpListNode->key;
		tempProcPass->label = newProcAttr->label;
		tempProcPass->privileges = newProcAttr->privileges;

		read_unlock(&pidListLock);

		copy_to_user((void *)dataPtr, tempProcPass, sizeof(procPass));

		kfree(tempProcPass);
		break;
		;;

		case 7:
		// dump the network stuff

		read_lock(&netListLock);

		tmpListNode = netListHead;
		// while loop for labels
		while(tmpListNode != NULL)
		{
			printk("Westsides: Network Label: %u\n", tmpListNode->key);
			netListNode = (listNode *)tmpListNode->data;
			while(netListNode != NULL)
			{
				newNetAttr = (netAttr *)netListNode->data;
				printk("WS: laddr: %u  lmask: %u  lport: %u  lrange: %u\n", (unsigned int)newNetAttr->laddr, (unsigned int)newNetAttr->lmask, newNetAttr->lport, newNetAttr->lrange);
				printk("WS: raddr: %u  rmask: %u  rport: %u  rrange: %u\n", (unsigned int)newNetAttr->raddr, (unsigned int)newNetAttr->rmask, newNetAttr->rport, newNetAttr->rrange);
				netListNode = netListNode->next;
			}
			tmpListNode = tmpListNode->next;
		}

		read_unlock(&netListLock);
		break;
		;;

		case 8:
		// return the number of network rules we have to the user

		read_lock(&netListLock);
		tmpListNode = netListHead;
		tmpVal = 0;
		// while loop for labels
		while(tmpListNode != NULL)
		{
			netListNode = (listNode *)tmpListNode->data;
			while(netListNode != NULL)
			{
				netListNode = netListNode->next;
				++tmpVal;
			}
			tmpListNode = tmpListNode->next;
		}
		read_unlock(&netListLock);

		copy_to_user((void *)dataPtr, &tmpVal, sizeof(unsigned int));
		break;
		;;

		case 9:
		// dump a big ugly network thing to the user

		read_lock(&netListLock);
		tmpListNode = netListHead;
		tmpVal = 0;
		// while loop for labels
		while(tmpListNode != NULL)
		{
			netListNode = (listNode *)tmpListNode->data;
			while(netListNode != NULL)
			{
				netListNode = netListNode->next;
				++tmpVal;
			}
			tmpListNode = tmpListNode->next;
		}
		if(tmpVal < 1)
		{
			read_unlock(&netListLock);
			return -1;
		}
		
		// tmpVal tells us how big this fucker really is
		realFilename = (char *)kmalloc(tmpVal * sizeof(netPassAttr), GFP_KERNEL);
		strPtr = realFilename;
		memset(realFilename, 0, tmpVal * sizeof(netPassAttr));
		pNetAttr = (netPassAttr *)realFilename;

		tmpListNode = netListHead;
		while(tmpListNode != NULL)
		{
			netListNode = (listNode *)tmpListNode->data;
			while(netListNode != NULL)
			{
				newNetAttr = (netAttr *)netListNode->data;

				pNetAttr->label = tmpListNode->key;
				pNetAttr->laddr = newNetAttr->laddr;
				pNetAttr->lmask = newNetAttr->lmask;
				pNetAttr->lport = newNetAttr->lport;
				pNetAttr->lrange = newNetAttr->lrange;
				pNetAttr->raddr = newNetAttr->raddr;
				pNetAttr->rmask = newNetAttr->rmask;
				pNetAttr->rport = newNetAttr->rport;
				pNetAttr->rrange = newNetAttr->rrange;
				
				strPtr += sizeof(netPassAttr);
				pNetAttr = (netPassAttr *)strPtr;
				netListNode = netListNode->next;
			}
			tmpListNode = tmpListNode->next;
		}
		read_unlock(&netListLock);

		copy_to_user((void *)dataPtr, realFilename, tmpVal * sizeof(netPassAttr));
		kfree(realFilename);
		break;
		;;

		case 10:
		// return the number of file objects

		read_lock(&fileListLock);
		fileTmpNode = fileListHead;
		tmpVal = 0;
		while(fileTmpNode != NULL)
		{
			tmpFileAttr = (fileAttr *)fileTmpNode->data;
			netListNode = tmpFileAttr->labelHead;
			while(netListNode != NULL)
			{
				++tmpVal;
				netListNode = netListNode->next;
			}
			fileTmpNode = fileTmpNode->next;
		}
		read_unlock(&fileListLock);

		copy_to_user((void *)dataPtr, &tmpVal, sizeof(unsigned int));

		break;
		;;

		case 11:
		// return a big honkin' file attr block

		read_lock(&fileListLock);

		fileTmpNode = fileListHead;
		tmpVal = 0;
		while(fileTmpNode != NULL)
		{
			tmpFileAttr = (fileAttr *)fileTmpNode->data;
			netListNode = tmpFileAttr->labelHead;
			while(netListNode != NULL)
			{
				++tmpVal;
				netListNode = netListNode->next;
			}
			fileTmpNode = fileTmpNode->next;
		}

		realFilename = (char *)kmalloc(tmpVal * sizeof(passFileAttr), GFP_KERNEL);
		memset(realFilename, 0, tmpVal * sizeof(passFileAttr));

		fileTmpNode = fileListHead;
		pFileAttr = (passFileAttr *)realFilename;
		strPtr = realFilename;
		while(fileTmpNode != NULL)
		{
			tmpFileAttr = (fileAttr *)fileTmpNode->data;
			netListNode = tmpFileAttr->labelHead;
			while(netListNode != NULL)
			{
				strncpy(pFileAttr->filename, tmpFileAttr->filename, 1024);
				pFileAttr->label = netListNode->key;
				strPtr += sizeof(passFileAttr);
				pFileAttr = (passFileAttr *)strPtr;
				netListNode = netListNode->next;
			}
			fileTmpNode = fileTmpNode->next;
		}

		read_unlock(&fileListLock);

		copy_to_user((void *)dataPtr, realFilename, tmpVal * sizeof(passFileAttr));
		kfree(realFilename);
		break;
		;;
	
		case 12:
		// delete a network setting
		pNetAttr = (netPassAttr *)dataPtr;

		write_lock(&netListLock);

		tmpListNode = netListHead;
		tmpVal = 0;
		tmpVal2 = 0;
		
		// find a node with the label we want to delete
		while(tmpListNode != NULL)
		{
			if(tmpListNode->key == pNetAttr->label)
			{
				// found the requested label
				netListNode = (listNode *)tmpListNode->data;
				tmpVal2 = 0;
				// look for the matching netAttr
				while(netListNode != NULL)
				{
					newNetAttr = (netAttr *)netListNode->data;
					if((pNetAttr->laddr == newNetAttr->laddr) && (pNetAttr->raddr == newNetAttr->raddr) && (pNetAttr->lmask == newNetAttr->lmask) && (pNetAttr->rmask == newNetAttr->rmask) && (pNetAttr->lport == newNetAttr->lport) && (pNetAttr->rport == newNetAttr->rport) && (pNetAttr->lrange == newNetAttr->lrange) && (pNetAttr->rrange == newNetAttr->rrange))
					{
						// got a match
						if(tmpVal2 == 0)
							tmpListNode->data = (void *)netListNode->next;
						else
							netListNode2->next = netListNode->next;
						kfree(netListNode);
						if(tmpListNode->data == NULL)
						{
							// cleaned out all the settings for this label, pull it off the list
							if(tmpVal == 0)
								netListHead = tmpListNode->next;
							else
								tmpListNode2->next = tmpListNode->next;
							kfree(tmpListNode);
						}
						write_unlock(&netListLock);
						return 0;
					}
					tmpVal2 = 1;
					netListNode2 = netListNode;
					netListNode = netListNode->next;
				}
			}
			tmpListNode2 = tmpListNode;
			tmpListNode = tmpListNode->next;
			tmpVal = 1;
		}

		write_unlock(&netListLock);
		break;
		;;

		case 13:
		// delete a file label setting
		tmpVal = 0;
		tmpVal2 = 0;

		write_lock(&fileListLock);

		fileTmpNode = fileListHead;
		pFileAttr = (passFileAttr *)dataPtr;
	
		// first find the filename that matches
		while(fileTmpNode != NULL)
		{
			tmpFileAttr = (fileAttr *)fileTmpNode->data;
			if(!strncmp(pFileAttr->filename, tmpFileAttr->filename, 1024))
			{
				// found the filename, now look for the label
				tmpListNode = (listNode *)tmpFileAttr->labelHead;
				tmpVal2 = 0;

				while(tmpListNode != NULL)
				{
					if((pFileAttr->label & LABEL_MASK) == (tmpListNode->key & LABEL_MASK))
					{
						// found the label
						if(tmpVal2 == 0)
							tmpFileAttr->labelHead = tmpListNode->next;						
						else
							tmpListNode2->next = tmpListNode-> next;
						kfree(tmpListNode);
						if(tmpFileAttr->labelHead == NULL)
						{
							// we deleted the last label for this filename
							if(tmpVal == 0)
							{
								fileListHead = fileTmpNode->next;
								if(fileListHead != NULL)
									fileListHead->prev = NULL;
							}
							else
							{
								// free a middle node
								fileTmpNode2->next = fileTmpNode->next;
								if(fileTmpNode != NULL)
									fileTmpNode->next->prev = fileTmpNode2;
							}
							kfree(fileTmpNode);
						}
						write_unlock(&fileListLock);
						return 0;
					}
					tmpListNode2 = tmpListNode;
					tmpVal2 = 1;
					tmpListNode = tmpListNode->next;
				}
			}
			fileTmpNode2 = fileTmpNode;
			tmpVal = 1;
			fileTmpNode = fileTmpNode->next;
		}

		write_unlock(&fileListLock);
		break;
		;;

		default:
		break;
		;;
	}	
	
	return 0;
}

static struct file_operations fileOps = {
	NULL,NULL, NULL, NULL, NULL, NULL, driverIoctl, NULL, driverOpen, 
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

// module functions
int init_module(void)
{
	int ctr = 0;

	// setup variables
	pidListHead = NULL;
	fileListHead = NULL;
	fileListTail = NULL;
	netListHead = NULL;

	printk("Initializing westsides...\n");
	// initialize driver
	if(register_chrdev(40, "westsides", &fileOps))
		return -EIO;

	// initialize our rw_locks
	rwlock_init(&pidListLock);
	rwlock_init(&fileListLock);
	rwlock_init(&netListLock);

	// setup system call tables

	my_sys_call_table = getSysCallTable();
	if(my_sys_call_table == NULL)
		return -EIO;

	saveSysCallTable(my_sys_call_table, orig_sys_call_table);

	// setup sec_sys_call_table
	for(ctr = 0; ctr < NR_syscalls; ++ctr)
		sec_sys_call_table[ctr] = secDefault;

	//
	// Syscalls controlled by privilege
	//
	sec_sys_call_table[SYS_setregid] = 	privilegeSETID;
	sec_sys_call_table[SYS_setgid] = 	privilegeSETID;
	sec_sys_call_table[SYS_setreuid] =	privilegeSETID;
	sec_sys_call_table[SYS_setuid] = 	privilegeSETID;
	sec_sys_call_table[SYS_setresuid] =	privilegeSETID;
	sec_sys_call_table[SYS_setresgid] =	privilegeSETID;
	sec_sys_call_table[SYS_setfsgid] = 	privilegeSETID;
	sec_sys_call_table[SYS_setfsuid] = 	privilegeSETID;
	sec_sys_call_table[SYS_setregid32] =	privilegeSETID;
	sec_sys_call_table[SYS_setgid32] = 	privilegeSETID;
	sec_sys_call_table[SYS_setreuid32] =	privilegeSETID;
	sec_sys_call_table[SYS_setuid32] = 	privilegeSETID;
	sec_sys_call_table[SYS_setresuid32] = 	privilegeSETID;
	sec_sys_call_table[SYS_setresgid32] = 	privilegeSETID;
	sec_sys_call_table[SYS_setfsgid32] = 	privilegeSETID;
	sec_sys_call_table[SYS_setfsuid32] = 	privilegeSETID;
	sec_sys_call_table[SYS_setpgid] = 	privilegeSETID;
	sec_sys_call_table[SYS_setgroups] =	privilegeSETID;
	sec_sys_call_table[SYS_create_module] =	privilegeMODULE;
	sec_sys_call_table[SYS_init_module] = 	privilegeMODULE;
	sec_sys_call_table[SYS_delete_module] =	privilegeMODULE;
	sec_sys_call_table[SYS_stime] = 	privilegeTIME;
	sec_sys_call_table[SYS_settimeofday] = 	privilegeTIME;
	sec_sys_call_table[SYS_reboot] = 	privilegeREBOOT;
	sec_sys_call_table[SYS_ioperm] = 	privilegeRAWIO;
	sec_sys_call_table[SYS_utime] = 	privilegeFILESYSTEM;
	sec_sys_call_table[SYS_chroot] =	privilegeFILESYSTEM;
	sec_sys_call_table[SYS_chmod] = 	privilegeFILESYSTEM;
	sec_sys_call_table[SYS_fchmod] =	privilegeFILESYSTEM;
	sec_sys_call_table[SYS_chown] = 	privilegeFILESYSTEM;
	sec_sys_call_table[SYS_fchown] =	privilegeFILESYSTEM;
	sec_sys_call_table[SYS_lchown] =	privilegeFILESYSTEM;
	sec_sys_call_table[SYS_swapoff] =	privilegeSWAP;
	sec_sys_call_table[SYS_swapon] = 	privilegeSWAP;
	sec_sys_call_table[SYS_syslog] = 	privilegeSYSLOG;
	sec_sys_call_table[SYS_setrlimit] =	privilegeRLIMIT;
	sec_sys_call_table[SYS_nfsservctl] =	privilegeNFSCTL;
	sec_sys_call_table[SYS_pivot_root] =	privilegeMOUNT;
	sec_sys_call_table[SYS_setpriority] =	privilegeNICE;
	sec_sys_call_table[SYS_nice] =	 	privilegeNICE;
	sec_sys_call_table[SYS_sethostname] =	privilegeNAME;
	sec_sys_call_table[SYS_setdomainname] =	privilegeNAME;
	sec_sys_call_table[SYS_iopl] =	 	privilegeRAWIO;

	//
	//  Syscalls controlled by file label
	//
	sec_sys_call_table[SYS_unlink] = 	secDeleteFile;
	sec_sys_call_table[SYS_rmdir] = 	secDeleteFile;
	sec_sys_call_table[SYS_truncate] = 	secWriteFile;
	sec_sys_call_table[SYS_truncate64] = 	secWriteFile;
	sec_sys_call_table[SYS_chdir] = 	secExecFile;
	sec_sys_call_table[SYS_creat] = 	secCreateFile;
	sec_sys_call_table[SYS_mkdir] = 	secCreateFile;

	//
	//  Miscellaneous syscalls
	//
	sec_sys_call_table[SYS_fork] = 		new_fork;
	sec_sys_call_table[SYS_clone] = 	new_clone;
	sec_sys_call_table[SYS_vfork] = 	new_vfork;
	sec_sys_call_table[SYS_mount] = 	new_mount;
	sec_sys_call_table[SYS_umount] = 	new_umount;
	sec_sys_call_table[SYS_exit] = 		new_exit;
	sec_sys_call_table[SYS_open] = 		new_open;
	sec_sys_call_table[SYS_link] = 		new_link;
	sec_sys_call_table[SYS_symlink] = 	new_symlink;
	sec_sys_call_table[SYS_adjtimex] = 	new_adjtimex;
	sec_sys_call_table[SYS_ptrace] = 	new_ptrace;
	//sec_sys_call_table[SYS_execve] = 	new_execve;
	sec_sys_call_table[SYS_quotactl] = 	new_quotactl;
	sec_sys_call_table[SYS_mknod] =		new_mknod;
	sec_sys_call_table[SYS_rename] = 	new_rename;
	sec_sys_call_table[SYS_uselib] = 	new_uselib;
	sec_sys_call_table[SYS_acct] = 		new_acct;
	sec_sys_call_table[SYS_ioctl] =		new_ioctl;
	sec_sys_call_table[SYS_kill] = 		new_kill;
	sec_sys_call_table[SYS_socketcall] = 	new_socketcall;

	trapSysCalls(my_sys_call_table);

	// these syscalls have to be handled special for now
	my_sys_call_table[SYS_fork] = (long)new_fork;
	old_fork = orig_sys_call_table[SYS_fork];
	my_sys_call_table[SYS_clone] = (long)new_clone;
	old_clone = orig_sys_call_table[SYS_clone];
	my_sys_call_table[SYS_vfork] = (long)new_vfork;
	old_vfork = orig_sys_call_table[SYS_vfork];
	
	return 0;
}

void cleanup_module(void)
{
	listNode *tmpListNode;
	listNode *tmpListNode2;
	dlistNode *tmpDlistNode;
	fileAttr *tmpFileAttr;
		

	// restore the original syscalls
	restoreSysCallTable(orig_sys_call_table, my_sys_call_table);
	kfree(orig_sys_call_table);

	// unregister the driver 
	unregister_chrdev(40, "westsides");

	// cleanup memory
	// cleanup process list
	write_lock(&pidListLock);
	while(pidListHead != NULL)
	{
		tmpListNode = pidListHead;
		pidListHead = pidListHead->next;
		// make sure to free the data!
		if(tmpListNode->data != NULL)
			kfree(tmpListNode->data);
		kfree(tmpListNode);
	}
	write_unlock(&pidListLock);

	// cleanup file list
	write_lock(&fileListLock);
	while(fileListHead != NULL)
	{
		tmpDlistNode = fileListHead;
		tmpFileAttr = (fileAttr *)tmpDlistNode->data;
		while(tmpFileAttr->labelHead != NULL)
		{
			tmpListNode = tmpFileAttr->labelHead;
			tmpFileAttr->labelHead = tmpListNode->next;
			kfree(tmpListNode);
		}
		kfree(tmpFileAttr);
		fileListHead = tmpDlistNode->next;
	}
	write_unlock(&fileListLock);

	// cleanup network list
	write_lock(&netListLock);
	while(netListHead != NULL)
	{
		tmpListNode = netListHead;
		netListHead = netListHead->next;
		while(tmpListNode->data != NULL)
		{
			tmpListNode2 = (listNode *)tmpListNode->data;
			tmpListNode->data = (void *)tmpListNode2->next;
			kfree(tmpListNode2->data);
			kfree(tmpListNode2);
		}
		kfree(tmpListNode);
	}
	write_unlock(&netListLock);
}
