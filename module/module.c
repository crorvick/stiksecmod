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
unsigned int *my_sys_call_table;

// process syscalls
// i386 specific fork
int (*old_fork)(struct pt_regs regs);
int (*old_clone)(struct pt_regs regs);
int (*old_vfork)(struct pt_regs regs);
long (*old_exit)(int error_code);
// i386 specific ptrace
int (*old_ptrace)(long request, long pid, long addr, long data);
// i386 spec execve
int (*old_execve)(struct pt_regs regs);

// privileged syscalls
// pretty sure ioperm and iopl are i386 specific
long (*old_setpriority)(int which, int who, int niceval);
int (*old_ioperm)(unsigned long from, unsigned long num, int turn_on);
int (*old_iopl)(unsigned long unused);
long (*old_setregid)(gid_t arg1, gid_t arg2);
long (*old_setgid)(gid_t arg1);
long (*old_setreuid)(uid_t arg1, uid_t arg2);
long (*old_setuid)(uid_t arg1);
long (*old_setresuid)(uid_t arg1, uid_t arg2, uid_t arg3);
long (*old_setresgid)(gid_t, gid_t arg2, gid_t arg3);
long (*old_setfsuid)(uid_t arg1);
long (*old_setfsgid)(gid_t arg1);
long (*old_setregid32)(gid_t arg1, gid_t arg2);
long (*old_setgid32)(gid_t arg1);
long (*old_setreuid32)(uid_t arg1, uid_t arg2);
long (*old_setuid32)(uid_t arg1);
long (*old_setresuid32)(uid_t arg1, uid_t arg2, uid_t arg3);
long (*old_setresgid32)(gid_t, gid_t arg2, gid_t arg3);
long (*old_setfsuid32)(uid_t arg1);
long (*old_setfsgid32)(gid_t arg1);
long (*old_setpgid)(pid_t pid, pid_t pgid);
long (*old_stime)(int * tptr);
long (*old_settimeofday)(struct timeval *tv, struct timezone *tz);
long (*old_adjtimex)(struct timex *txc_p);
unsigned long (*old_create_module)(const char *name_user, size_t size);
long (*old_init_module)(const char *name_user, struct module *mod_user);
long (*old_delete_module)(const char *name_user);
long (*old_mount)(char * dev_name, char * dir_name, char * type, unsigned long flags, void * data);
long (*old_umount)(char * name, int flags);
long (*old_reboot)(int magic1, int magic2, unsigned int cmd, void * arg);
long (*old_quotactl)(int cmd, const char *special, int id, caddr_t addr);
long (*old_setrlimit)(unsigned int resource, struct rlimit *rlim);
// some fcntl may need to be protected in the future - F_SETOWN and F_SETSIG you already can't drop APPEND, so we don't worry about that
long (*old_mknod)(const char * filename, int mode, dev_t dev);
long (*old_swapoff)(const char * specialfile);
long (*old_swapon)(const char * specialfile, int swap_flags);
long (*old_syslog)(int type, char * buf, int len);
long (*old_acct)(const char *name);
int (*old_nfsservctl)(int cmd, void *argp, void *resp);
long (*old_pivot_root)(const char *new_root, const char *put_old);
long (*old_ioctl)(unsigned int fd, unsigned int cmd, unsigned long arg);
long (*old_setgroups)(int gidsetsize, gid_t *grouplist);
long (*old_newuname)(struct new_utsname * name);
long (*old_sethostname)(char *name, int len);
long (*old_setdomainname)(char *name, int len);
long (*old_nice)(int increment);
long (*old_sysctl)(struct __sysctl_args *args);
long (*old_pciconfig_write)(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void *buf);
long (*old_kill)(int pid, int sig);
long (*old_fchdir)(unsigned int fd);

// file syscalls
long (*old_open)(const char * filename, int flags, int mode);
long (*old_rename)(const char * oldname, const char * newname);
long (*old_uselib)(const char * library);
long (*old_truncate)(const char * path, unsigned long length);
long (*old_truncate64)(const char * path, loff_t length);
long (*old_utime)(char * filename, struct utimbuf * times);
long (*old_utimes)(char * filename, struct timeval * utimes);
// access is only for prettiness
long (*old_chdir)(const char * filename);
long (*old_chroot)(const char * filename);
long (*old_fchmod)(unsigned int fd, mode_t mode);
long (*old_chmod)(const char * filename, mode_t mode);
long (*old_chown)(const char * filename, uid_t user, gid_t group);
long (*old_lchown)(const char * filename, uid_t user, gid_t group);
long (*old_fchown)(unsigned int fd, uid_t user, gid_t group);
long (*old_creat)(const char * pathname, int mode);
long (*old_mkdir)(const char * pathname, int mode);
long (*old_link)(const char * oldname, const char * newname);
long (*old_unlink)(const char * pathname);
long (*old_rmdir)(const char * pathname);
long (*old_symlink)(const char * oldname, const char * newname);

// network syscalls
long (*old_connect)(int fd, struct sockaddr *uservaddr, int addrlen);
long (*old_bind)(int fd, struct sockaddr *umyaddr, int addrlen);
long (*old_socketcall)(int call, unsigned long *args);
// getpeername() might let you leak information
// there's a bunch more network calls to take care of

// We don't yet support labeled IPC - which could leave a system open to some memory based information attacks

int new_bind(int fd, struct sockaddr *umyaddr, int addrlen);
int new_connect(int fd, struct sockaddr *uservaddr, int addrlen);
int new_sendto(int fd, void * buff, size_t len, unsigned flags, struct sockaddr *addr, int addr_len);

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

	return (*old_socketcall)(call, args);
}

long new_fchdir(unsigned int fd)
{
	// once we find a nice way to dereference the file descriptor we'll do this
	return (*old_fchdir)(fd);
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
	return (*old_kill)(pid, sig);
}
	
long new_pciconfig_write(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void *buf)
{
        if(checkPrivilege(PRIVILEGE_PCICONFIG) < 1)
        {
                return 0;
        }
	return (*old_pciconfig_write)(bus, dfn, off, len, buf);
}

long new_sysctl(struct __sysctl_args *args)
{
	// screw you, use /proc
        if(checkPrivilege(PRIVILEGE_SYSCTL) < 1)
        {
                return 0;
        }
	return (*old_sysctl)(args);
}

long new_nice(int increment)
{
        if(checkPrivilege(PRIVILEGE_NICE) < 1)
        {
                return 0;
        }
	return (*old_nice)(increment);
}

long new_setdomainname(char *name, int len)
{
        if(checkPrivilege(PRIVILEGE_NAME) < 1)
        {
                return 0;
        }
	return (*old_setdomainname)(name, len);
}

long new_sethostname(char *name, int len)
{
        if(checkPrivilege(PRIVILEGE_NAME) < 1)
        {
                return 0;
        }
	return (*old_sethostname)(name, len);
}

long new_newuname(struct new_utsname * name)
{
        if(checkPrivilege(PRIVILEGE_NAME) < 1)
        {
                return 0;
        }
	return (*old_newuname)(name);
}
	
long new_setgroups(int gidsetsize, gid_t *grouplist)
{
        if(checkPrivilege(PRIVILEGE_SETID) < 1)
        {
                return 0;
        }
	return (*old_setgroups)(gidsetsize, grouplist);
}

long new_setpgid(pid_t pid, pid_t pgid)
{
        if(checkPrivilege(PRIVILEGE_SETID) < 1)
        {
                return 0;
        }
	return (*old_setpgid)(pid, pgid);
}

long new_setpriority(int which, int who, int niceval)
{
	// in the future we want to bring this into line with the kernel so you can nice the process
        if(checkPrivilege(PRIVILEGE_NICE) < 1)
        {
                return 0;
        }
	return(*old_setpriority)(which, who, niceval);
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
                	return 0;
        	}
	}
	return (*old_ioctl)(fd, cmd, arg);
}

int new_pivot_root(const char *new_root, const char *put_old)
{
        if(checkPrivilege(PRIVILEGE_MOUNT) < 1)
        {
                return 0;
        }
	return (*old_pivot_root)(new_root, put_old);
}

int new_nfsservctl(int cmd, void *argp, void *resp)
{
        if(checkPrivilege(PRIVILEGE_NFSCTL) < 1)
        {
                return 0;
        }
	return (*old_nfsservctl)(cmd, argp, resp);
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

long new_setrlimit(unsigned int resource, struct rlimit *rlim)
{
        if(checkPrivilege(PRIVILEGE_RLIMIT) < 1)
        {
                return 0;
        }
	return (*old_setrlimit)(resource, rlim);
}

long new_acct(const char *name)
{
	// we need privilege and write permission on the file
	unsigned int processLabel, fileLabel;
	char realFilename[1024];

        if(checkPrivilege(PRIVILEGE_ACCT) < 1)
        {
                return 0;
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
		return 0;

acctReturn:
	return (*old_acct)(name);
}

long new_mkdir(const char * pathname, int mode)
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
		return 0;

mkdirReturn:
	return (*old_mkdir)(pathname, mode);
}

long new_creat(const char * pathname, int mode)
{
	// we need write permission on the directory to create a file
	unsigned int processLabel, fileLabel;
	char realFilename[1024], *realFilePtr;
	
	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto creatReturn;

        // lets resolve the real path of oldname
	if(realFileName(pathname, realFilename, 1024) < 1)
		goto creatReturn;

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
		return 0;

creatReturn:
	return (*old_creat)(pathname, mode);
}

long new_syslog(int type, char * buf, int len)
{
        if(checkPrivilege(PRIVILEGE_SYSLOG) < 1)
        {
                return 0;
        }
	return (*old_syslog)(type, buf, len);
}

long new_swapoff(const char * specialfile)
{
        if(checkPrivilege(PRIVILEGE_SWAP) < 1)
        {
                return 0;
        }
	return (*old_swapoff)(specialfile);
}

long new_swapon(const char * specialfile, int swap_flags)
{
        if(checkPrivilege(PRIVILEGE_SWAP) < 1)
        {
                return 0;
        }
	return (*old_swapon)(specialfile, swap_flags);
}

long new_chroot(const char * filename)
{
        if(checkPrivilege(PRIVILEGE_FILESYSTEM) < 1)
        {
                return 0;
        }
	return (*old_chroot)(filename);
}
	
long new_fchmod(unsigned int fd, mode_t mode)
{
        if(checkPrivilege(PRIVILEGE_FILESYSTEM) < 1)
        {
                return 0;
        }
	return (*old_fchmod)(fd, mode);
}

long new_chmod(const char * filename, mode_t mode)
{
        if(checkPrivilege(PRIVILEGE_FILESYSTEM) < 1)
        {
                return 0;
        }
	return (*old_chmod)(filename, mode);
}

long new_chown(const char * filename, uid_t user, gid_t group)
{
        if(checkPrivilege(PRIVILEGE_FILESYSTEM) < 1)
        {
                return 0;
        }
	return (*old_chown)(filename, user, group);
}

long new_lchown(const char * filename, uid_t user, gid_t group)
{
        if(checkPrivilege(PRIVILEGE_FILESYSTEM) < 1)
        {
                return 0;
        }
	return (*old_lchown)(filename, user, group);
}

long new_fchown(unsigned int fd, uid_t user, gid_t group)
{
        if(checkPrivilege(PRIVILEGE_FILESYSTEM) < 1)
        {
                return 0;
        }
	return (*old_fchown)(fd, user, group);
}

long new_chdir(const char * filename)
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

	// now that we've resolved the real pathname, we need to check if we have delete on the file,
	// then write on the directory its in
	// get the filelabel
	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_EXEC) < 1)
		return 0;

chdirReturn:
	return (*old_chdir)(filename);
}

long new_utime(char * filename, struct utimbuf * times)
{
        if(checkPrivilege(PRIVILEGE_FILESYSTEM) < 1)
        {
                return 0;
        }
	return (*old_utime)(filename, times);
}

long new_utimes(char * filename, struct timeval * utimes)
{
        if(checkPrivilege(PRIVILEGE_FILESYSTEM) < 1)
        {
                return 0;
        }
	return (*old_utimes)(filename, utimes);
}

long new_truncate64(const char * path, loff_t length)
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

	// now that we've resolved the real pathname, we need to check if we have delete on the file,
	// then write on the directory its in
	// get the filelabel
	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return 0;

truncate64Return:
	return (*old_truncate64)(path, length);
}

long new_truncate(const char * path, unsigned long length)
{
	// we need write on the file
	unsigned int processLabel, fileLabel;
	char realFilename[1024];
	
	// get our current process label
	if(getProcessLabel(&processLabel, current->pid) < 1)
		goto truncateReturn;

        // lets resolve the real path of oldname
	if(realFileName(path, realFilename, 1024) < 1)
		goto truncateReturn;

	// now that we've resolved the real pathname, we need to check if we have delete on the file,
	// then write on the directory its in
	// get the filelabel
	if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);
	
	// we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_WRITE) < 1)
		return 0;

truncateReturn:
	return (*old_truncate)(path, length);
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
		return 0;

	if(fileLabelAccess(processLabel, fileLabel, LABEL_EXEC) < 1)
		return 0;

uselibReturn:
	 return (*old_uselib)(library);
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
		return 0;

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
		return 0;

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
		return 0;

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
		return 0;

renameReturn:
	return (*old_rename)(oldname, newname);
}

int new_fork(struct pt_regs regs)
{
	int newPid;
	// we really should build over the basic types so we can call things like addProcess()
	listNode *pidNewNode;
	listNode *pidTempNode;
	procAttr *newProcAttr; 
	procAttr *tempProcAttr; 

	// hmm wonder if there is a race condition caused by doing fork first
	// i guess no, esp if userspace is waiting on a return from this syscall
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
	newPid =(*old_vfork)(regs);

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
                return 0;

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
		return 0;

mknodReturn:
	return (*old_mknod)(filename, mode, dev);
}
	
long new_quotactl(int cmd, const char *special, int id, caddr_t addr)
{
	// we only privilege restrict some quota operations
	int cmds = cmd >> SUBCMDSHIFT;
	if(cmds & (Q_QUOTAON | Q_QUOTAOFF | Q_SETQUOTA | Q_SETQLIM | Q_SETUSE ))
	{
		if(checkPrivilege(PRIVILEGE_FSQUOTA) < 1)
        	{
                	return 0;
        	}
	}
	return (*old_quotactl)(cmd, special, id, addr);
}

// ptrace should definitely be restricted by label - i'm sure someone will debate whether it needs to be restricted by privilege as well
int new_ptrace(long request, long pid, long addr, long data)
{
	unsigned int currentLabel, traceLabel;
	if(getProcessLabel(&currentLabel, current->pid) < 1)
		// we are unprotected - go for it
		goto ptraceReturn;
	if(getProcessLabel(&traceLabel, (short int)pid) < 1)
		// protected tracing unprotected - no way
		return 0;
	if(currentLabel != traceLabel)
		//different labels - no way
		return 0;
ptraceReturn:
	return (*old_ptrace)(request, pid, addr, data);
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
	//return (*old_execve)(regs);
	//retVal = (*old_execve)(regs);
	return retVal;
}
	

// hope these io perm bit calls don't break anything :)
int new_ioperm(unsigned long from, unsigned long num, int turn_on)
{
        if(checkPrivilege(PRIVILEGE_RAWIO) < 1)
        {
                return 0;
        }
	return (*old_ioperm)(from, num, turn_on);
}

int new_iopl(unsigned long unused)
{
        if(checkPrivilege(PRIVILEGE_RAWIO) < 1)
        {
                return 0;
        }
	return (*old_iopl)(unused);
}

long new_reboot(int magic1, int magic2, unsigned int cmd, void * arg)
{
        if(checkPrivilege(PRIVILEGE_REBOOT) < 1)
        {
                return 0;
        }
        return (*old_reboot)(magic1, magic2, cmd, arg);
}

long new_adjtimex(struct timex *txc_p)
{
        if(txc_p->modes && (checkPrivilege(PRIVILEGE_TIME) < 1))
        {
                return 0;
        }
	return (*old_adjtimex)(txc_p);
}
	
long new_settimeofday(struct timeval *tv, struct timezone *tz)
{
        if(checkPrivilege(PRIVILEGE_TIME) < 1)
        {
                return 0;
        }
	return (*old_settimeofday)(tv, tz);
}

long new_stime(int * tptr)
{
	if(checkPrivilege(PRIVILEGE_TIME) < 1)
	{
		return 0;
	}
	return (*old_stime)(tptr);
}

long new_setregid(gid_t arg1, gid_t arg2)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setregid)(arg1, arg2);
}

long new_setregid32(gid_t arg1, gid_t arg2)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setregid32)(arg1, arg2);
}

long new_setgid(gid_t arg1)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setgid)(arg1);
}

long new_setgid32(gid_t arg1)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setgid32)(arg1);
}

long new_setreuid(uid_t arg1, uid_t arg2)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setreuid)(arg1, arg2);
}

long new_setreuid32(uid_t arg1, uid_t arg2)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setreuid32)(arg1, arg2);
}

long new_setuid(uid_t arg1)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setuid)(arg1);
}

long new_setuid32(uid_t arg1)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setuid32)(arg1);
}

long new_setresuid(uid_t arg1, uid_t arg2, uid_t arg3)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setresuid)(arg1, arg2, arg3);
}

long new_setresuid32(uid_t arg1, uid_t arg2, uid_t arg3)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setresuid32)(arg1, arg2, arg3);
}


long new_setresgid(arg1, arg2, arg3)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setresgid)(arg1, arg2, arg3);
}

long new_setresgid32(arg1, arg2, arg3)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setresgid32)(arg1, arg2, arg3);
}

long new_setfsuid(uid_t arg1)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setfsuid)(arg1);
}

long new_setfsuid32(uid_t arg1)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setfsuid32)(arg1);
}

long new_setfsgid(gid_t arg1)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setfsgid)(arg1);
}

long new_setfsgid32(gid_t arg1)
{
	if(checkPrivilege(PRIVILEGE_SETID) < 1)
	{
		return 0;
	}
	return (*old_setfsgid32)(arg1);
}

unsigned long new_create_module(const char *name_user, size_t size)
{
	if(checkPrivilege(PRIVILEGE_MODULE) < 1)
	{
		return 0;
	}
	return (*old_create_module)(name_user, size);
}
	
long new_init_module(const char *name_user, struct module *mod_user)
{
	if(checkPrivilege(PRIVILEGE_MODULE) < 1)
	{
		return 0;
	}
	return (*old_init_module)(name_user, mod_user);
}

long new_delete_module(const char *name_user)
{
	if(checkPrivilege(PRIVILEGE_MODULE) < 1)
	{
		return 0;
	}
	return (*old_delete_module)(name_user);
}

long new_mount(char * dev_name, char * dir_name, char * type, unsigned long flags, void * data)
{
	if(checkPrivilege(PRIVILEGE_MOUNT) < 1)
	{
		return 0;
	}
	// we also want to check filesystem rights on a mount

	return (*old_mount)(dev_name, dir_name, type, flags, data);
}

long new_umount(char * name, int flags)
{
	if(checkPrivilege(PRIVILEGE_MOUNT) < 1)
	{
		return 0;
	}
	// we also want to check filesystem rights on a umount

	return (*old_umount)(name, flags);
}

long new_exit(int error_code)
{
	long retVal;
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

	retVal = (*old_exit)(error_code);
	
	// we probably don't ever get here
	return retVal;
}

long new_open(const char * filename, int flags, int mode)
{
	unsigned int processLabel, fileLabel;
	char realFilename[1024];
	long retVal;

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
	retVal = (*old_open)(filename,flags,mode);
	return retVal;
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
        return (*old_symlink)(oldname, newname);
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

	return (*old_link)(oldname, newname);
}

long new_unlink(const char * pathname)
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
		return 0;

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
		return 0;

unlinkReturn:
	return (*old_unlink)(pathname);
}

long new_rmdir(const char * pathname)
{
        char realFilename[1024], *realFilePtr;
        unsigned int processLabel, fileLabel;

        // get our current process label
        if(getProcessLabel(&processLabel, current->pid) < 1)
                goto rmdirReturn;

        // lets resolve the real path of pathname
        if(realFileName(pathname, realFilename, 1024) < 1)
                goto rmdirReturn;

        // now that we've resolve the real pathname, we need to check if we have delete on the file,
        // then write on the directory its in
        // get the filelabel
        if(getFileLabel(realFilename, processLabel, &fileLabel) < 1)
		fileLabel = (processLabel & LABEL_MASK);

        // we have this label now lets check access
	if(fileLabelAccess(processLabel, fileLabel, LABEL_DELETE) < 1)
		return 0;

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
		return 0;

rmdirReturn:
        return (*old_rmdir)(pathname);
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
	unsigned int sys_call_off;
	int ctr = 0;

	struct {
		unsigned short limit;
		unsigned int base;
	} __attribute__ ((packed)) idtr;

	struct {
        	unsigned short off1;
        	unsigned short sel;
        	unsigned char none,flags;
        	unsigned short off2;
	} __attribute__ ((packed)) *idt;

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

	// Since in the future we will so rudely be denied access to
	// sys_call_table, we have to go ahead and find it
	// This code is borrowed from sd and devik's article
	// in Phrack 58
	asm ("sidt %0" : "=m" (idtr));
	(unsigned int)idt = (unsigned int)(idtr.base+8*0x80);
	sys_call_off = (idt->off2 << 16) | idt->off1;
	while(1)
	{
		// could probably use memcmp
		if(!strncmp((char *)sys_call_off,"\xff\x14\x85",3))
			break;
		++sys_call_off;
		++ctr;
		if(ctr > 400)
		{
			printk("Westsides: No system call table found\n");
			unregister_chrdev(40, "westsides");
			return -EIO;
		}
	}
	my_sys_call_table = (unsigned int *)*(unsigned int *)(sys_call_off + 3);

	// setup syscall table
	old_fork = (void *)my_sys_call_table[SYS_fork];
	my_sys_call_table[SYS_fork] = (unsigned int)new_fork;

	old_clone = (void *)my_sys_call_table[SYS_clone];
	my_sys_call_table[SYS_clone] = (unsigned int)new_clone;

	old_vfork = (void *)my_sys_call_table[SYS_vfork];
	my_sys_call_table[SYS_vfork] = (unsigned int)new_vfork;

	old_setregid = (void *)my_sys_call_table[SYS_setregid];
	my_sys_call_table[SYS_setregid] = (unsigned int)new_setregid;

	old_setgid = (void *)my_sys_call_table[SYS_setgid];
	my_sys_call_table[SYS_setgid] = (unsigned int)new_setgid;

	old_setreuid = (void *)my_sys_call_table[SYS_setreuid];
	my_sys_call_table[SYS_setreuid] = (unsigned int)new_setreuid;

	old_setuid = (void *)my_sys_call_table[SYS_setuid];
	my_sys_call_table[SYS_setuid] = (unsigned int)new_setuid;

	old_setresuid = (void *)my_sys_call_table[SYS_setresuid];
	my_sys_call_table[SYS_setresuid] = (unsigned int)new_setresuid;

	old_setresgid = (void *)my_sys_call_table[SYS_setresgid];
	my_sys_call_table[SYS_setresgid] = (unsigned int)new_setresgid;

	old_setfsgid = (void *)my_sys_call_table[SYS_setfsgid];
	my_sys_call_table[SYS_setfsgid] = (unsigned int)new_setfsgid;

	old_setfsuid = (void *)my_sys_call_table[SYS_setfsuid];
	my_sys_call_table[SYS_setfsuid] = (unsigned int)new_setfsuid;

	old_setregid32 = (void *)my_sys_call_table[SYS_setregid32];
	my_sys_call_table[SYS_setregid32] = (unsigned int)new_setregid32;

	old_setgid32 = (void *)my_sys_call_table[SYS_setgid32];
	my_sys_call_table[SYS_setgid32] = (unsigned int)new_setgid;

	old_setreuid32 = (void *)my_sys_call_table[SYS_setreuid32];
	my_sys_call_table[SYS_setreuid32] = (unsigned int)new_setreuid32;

	old_setuid32 = (void *)my_sys_call_table[SYS_setuid32];
	my_sys_call_table[SYS_setuid32] = (unsigned int)new_setuid32;

	old_setresuid32 = (void *)my_sys_call_table[SYS_setresuid32];
	my_sys_call_table[SYS_setresuid32] = (unsigned int)new_setresuid32;

	old_setresgid32 = (void *)my_sys_call_table[SYS_setresgid32];
	my_sys_call_table[SYS_setresgid32] = (unsigned int)new_setresgid32;

	old_setfsgid32 = (void *)my_sys_call_table[SYS_setfsgid32];
	my_sys_call_table[SYS_setfsgid32] = (unsigned int)new_setfsgid32;

	old_setfsuid32 = (void *)my_sys_call_table[SYS_setfsuid32];
	my_sys_call_table[SYS_setfsuid32] = (unsigned int)new_setfsuid32;

	old_create_module = (void *)my_sys_call_table[SYS_create_module];
	my_sys_call_table[SYS_create_module] = (unsigned int)new_create_module;

	old_init_module = (void *)my_sys_call_table[SYS_init_module];
	my_sys_call_table[SYS_init_module] = (unsigned int)new_init_module;

	// no point in having it segfault every time we rmmod it
	old_delete_module = (void *)my_sys_call_table[SYS_delete_module];
	// my_sys_call_table[SYS_delete_module] = (unsigned int)new_delete_module;

	old_mount = (void *)my_sys_call_table[SYS_mount];
	my_sys_call_table[SYS_mount] = (unsigned int)new_mount;

	old_umount = (void *)my_sys_call_table[SYS_umount];
	my_sys_call_table[SYS_umount] = (unsigned int)new_umount;

	old_exit = (void *)my_sys_call_table[SYS_exit];
	my_sys_call_table[SYS_exit] = (unsigned int)new_exit;

	old_open = (void *)my_sys_call_table[SYS_open];
	my_sys_call_table[SYS_open] = (unsigned int)new_open;

	// old_connect = my_sys_call_table[SYS_connect];
	// my_sys_call_table[SYS_connect] = (unsigned int)new_connect;

	old_link = (void *)my_sys_call_table[SYS_link];
	my_sys_call_table[SYS_link] = (unsigned int)new_link;

	old_symlink = (void *)my_sys_call_table[SYS_symlink];
	my_sys_call_table[SYS_symlink] = (unsigned int)new_symlink;

	old_unlink = (void *)my_sys_call_table[SYS_unlink];
	my_sys_call_table[SYS_unlink] = (unsigned int)new_unlink;

	old_stime = (void *)my_sys_call_table[SYS_stime];
	my_sys_call_table[SYS_stime] = (unsigned int)new_stime;

	old_settimeofday = (void *)my_sys_call_table[SYS_settimeofday];
	my_sys_call_table[SYS_settimeofday] = (unsigned int)new_settimeofday;

	old_adjtimex = (void *)my_sys_call_table[SYS_adjtimex];
	my_sys_call_table[SYS_adjtimex] = (unsigned int)new_adjtimex;

	old_reboot = (void *)my_sys_call_table[SYS_reboot];
	my_sys_call_table[SYS_reboot] = (unsigned int)new_reboot;

	old_ioperm = (void *)my_sys_call_table[SYS_ioperm];
	my_sys_call_table[SYS_ioperm] = (unsigned int)new_ioperm;

	old_ptrace = (void *)my_sys_call_table[SYS_ptrace];
	my_sys_call_table[SYS_ptrace] = (unsigned int)new_ptrace;

	old_execve = (void *)my_sys_call_table[SYS_execve];
	// execve is causing userspace segfaults. hmm
	my_sys_call_table[SYS_execve] = (unsigned int)new_execve;

	old_quotactl = (void *)my_sys_call_table[SYS_quotactl];
	my_sys_call_table[SYS_quotactl] = (unsigned int)new_quotactl;

	old_mknod = (void *)my_sys_call_table[SYS_mknod];
	my_sys_call_table[SYS_mknod] = (unsigned int)new_mknod;

	old_rmdir = (void *)my_sys_call_table[SYS_rmdir];
	my_sys_call_table[SYS_rmdir] = (unsigned int)new_rmdir;

	old_rename = (void *)my_sys_call_table[SYS_rename];
	my_sys_call_table[SYS_rename] = (unsigned int)new_rename;

	old_uselib = (void *)my_sys_call_table[SYS_uselib];
	my_sys_call_table[SYS_uselib] = (unsigned int)new_uselib;

	old_truncate = (void *)my_sys_call_table[SYS_truncate];
	my_sys_call_table[SYS_truncate] = (unsigned int)new_truncate;

	old_truncate64 = (void *)my_sys_call_table[SYS_truncate64];
	my_sys_call_table[SYS_truncate64] = (unsigned int)new_truncate64;

	old_utime = (void *)my_sys_call_table[SYS_utime];
	my_sys_call_table[SYS_utime] = (unsigned int)new_utime;

	//old_utimes = my_sys_call_table[SYS_utimes];
	//my_sys_call_table[SYS_utimes] = (unsigned int)new_utimes;

	old_chdir = (void *)my_sys_call_table[SYS_chdir];
	my_sys_call_table[SYS_chdir] = (unsigned int)new_chdir;

	old_chroot = (void *)my_sys_call_table[SYS_chroot];
	my_sys_call_table[SYS_chroot] = (unsigned int)new_chroot;

	old_chmod = (void *)my_sys_call_table[SYS_chmod];
	my_sys_call_table[SYS_chmod] = (unsigned int)new_chmod;

	old_fchmod = (void *)my_sys_call_table[SYS_fchmod];
	my_sys_call_table[SYS_fchmod] = (unsigned int)new_fchmod;

	old_chown = (void *)my_sys_call_table[SYS_chown];
	my_sys_call_table[SYS_chown] = (unsigned int)new_chown;

	old_fchown = (void *)my_sys_call_table[SYS_fchown];
	my_sys_call_table[SYS_fchown] = (unsigned int)new_fchown;

	old_lchown = (void *)my_sys_call_table[SYS_lchown];
	my_sys_call_table[SYS_lchown] = (unsigned int)new_lchown;

	old_swapoff = (void *)my_sys_call_table[SYS_swapoff];
	my_sys_call_table[SYS_swapoff] = (unsigned int)new_swapoff;

	old_swapon = (void *)my_sys_call_table[SYS_swapon];
	my_sys_call_table[SYS_swapon] = (unsigned int)new_swapon;

	old_syslog = (void *)my_sys_call_table[SYS_syslog];
	my_sys_call_table[SYS_syslog] = (unsigned int)new_syslog;

	old_creat = (void *)my_sys_call_table[SYS_creat];
	my_sys_call_table[SYS_creat] = (unsigned int)new_creat;

	old_mkdir = (void *)my_sys_call_table[SYS_mkdir];
	my_sys_call_table[SYS_mkdir] = (unsigned int)new_mkdir;

	old_acct = (void *)my_sys_call_table[SYS_acct];
	my_sys_call_table[SYS_acct] = (unsigned int)new_acct;

	old_setrlimit = (void *)my_sys_call_table[SYS_setrlimit];
	my_sys_call_table[SYS_setrlimit] = (unsigned int)new_setrlimit;

	// old_bind = (void *)my_sys_call_table[SYS_bind];
	// my_sys_call_table[SYS_bind] = (unsigned int)new_bind;

	old_nfsservctl = (void *)my_sys_call_table[SYS_nfsservctl];
	my_sys_call_table[SYS_nfsservctl] = (unsigned int)new_nfsservctl;

	old_pivot_root = (void *)my_sys_call_table[SYS_pivot_root];
	my_sys_call_table[SYS_pivot_root] = (unsigned int)new_pivot_root;

	old_ioctl = (void *)my_sys_call_table[SYS_ioctl];
	my_sys_call_table[SYS_ioctl] = (unsigned int)new_ioctl;

	old_setpriority = (void *)my_sys_call_table[SYS_setpriority];
	my_sys_call_table[SYS_setpriority] = (unsigned int)new_setpriority;

	old_setpgid = (void *)my_sys_call_table[SYS_setpgid];
	my_sys_call_table[SYS_setpgid] = (unsigned int)new_setpgid;

	old_setgroups = (void *)my_sys_call_table[SYS_setgroups];
	my_sys_call_table[SYS_setgroups] = (unsigned int)new_setgroups;

	//old_newuname = (void *)my_sys_call_table[SYS_newuname];
	//my_sys_call_table[SYS_newuname] = (unsigned int)new_newuname;

	old_sethostname = (void *)my_sys_call_table[SYS_sethostname];
	my_sys_call_table[SYS_sethostname] = (unsigned int)new_sethostname;

	old_setdomainname = (void *)my_sys_call_table[SYS_setdomainname];
	my_sys_call_table[SYS_setdomainname] = (unsigned int)new_setdomainname;

	old_nice = (void *)my_sys_call_table[SYS_nice];
	my_sys_call_table[SYS_nice] = (unsigned int)new_nice;

	//old_sysctl = (void *)my_sys_call_table[SYS_sysctl];
	//my_sys_call_table[SYS_sysctl] = (unsigned int)new_sysctl;

	//old_pciconfig_write = (void *)my_sys_call_table[SYS_pciconfig_write];
	//my_sys_call_table[SYS_pciconfig_write] = (unsigned int)new_pciconfig_write;

	old_kill = (void *)my_sys_call_table[SYS_kill];
	my_sys_call_table[SYS_kill] = (unsigned int)new_kill;

	// old_fchdir = (void *)my_sys_call_table[SYS_fchdir];
	// my_sys_call_table[SYS_fchdir] = (unsigned int)new_fchdir;

	old_socketcall = (void *)my_sys_call_table[SYS_socketcall];
	my_sys_call_table[SYS_socketcall] = (unsigned int)new_socketcall;

	return 0;
}

void cleanup_module(void)
{
	listNode *tmpListNode;
	listNode *tmpListNode2;
	dlistNode *tmpDlistNode;
	fileAttr *tmpFileAttr;
		
	// restore the original syscalls
	my_sys_call_table[SYS_fork] = (unsigned int)old_fork;
	my_sys_call_table[SYS_clone] = (unsigned int)old_clone;
	my_sys_call_table[SYS_vfork] = (unsigned int)old_vfork;
	my_sys_call_table[SYS_setregid] = (unsigned int)old_setregid;
	my_sys_call_table[SYS_setgid] = (unsigned int)old_setgid;
	my_sys_call_table[SYS_setreuid] = (unsigned int)old_setreuid;
	my_sys_call_table[SYS_setuid] = (unsigned int)old_setuid;
	my_sys_call_table[SYS_setresuid] = (unsigned int)old_setresuid;
	my_sys_call_table[SYS_setresgid] = (unsigned int)old_setresgid;
	my_sys_call_table[SYS_setfsgid] = (unsigned int)old_setfsgid;
	my_sys_call_table[SYS_setfsuid] = (unsigned int)old_setfsuid;
	my_sys_call_table[SYS_setregid32] = (unsigned int)old_setregid32;
	my_sys_call_table[SYS_setgid32] = (unsigned int)old_setgid32;
	my_sys_call_table[SYS_setreuid32] = (unsigned int)old_setreuid32;
	my_sys_call_table[SYS_setuid32] = (unsigned int)old_setuid32;
	my_sys_call_table[SYS_setresuid32] = (unsigned int)old_setresuid32;
	my_sys_call_table[SYS_setresgid32] = (unsigned int)old_setresgid32;
	my_sys_call_table[SYS_setfsgid32] = (unsigned int)old_setfsgid32;
	my_sys_call_table[SYS_setfsuid32] = (unsigned int)old_setfsuid32;
	my_sys_call_table[SYS_create_module] = (unsigned int)old_create_module;
	my_sys_call_table[SYS_init_module] = (unsigned int)old_init_module;
	my_sys_call_table[SYS_delete_module] = (unsigned int)old_delete_module;
	my_sys_call_table[SYS_mount] = (unsigned int)old_mount;
	my_sys_call_table[SYS_umount] = (unsigned int)old_umount;
	my_sys_call_table[SYS_exit] = (unsigned int)old_exit;
	my_sys_call_table[SYS_open] = (unsigned int)old_open;
	// my_sys_call_table[SYS_connect] = (unsigned int)old_connect;
	my_sys_call_table[SYS_link] = (unsigned int)old_link;
	my_sys_call_table[SYS_symlink] = (unsigned int)old_symlink;
	my_sys_call_table[SYS_unlink] = (unsigned int)old_unlink;
	my_sys_call_table[SYS_stime] = (unsigned int)old_stime;
	my_sys_call_table[SYS_settimeofday] = (unsigned int)old_settimeofday;
	my_sys_call_table[SYS_adjtimex] = (unsigned int)old_adjtimex;
	my_sys_call_table[SYS_reboot] = (unsigned int)old_reboot;
	my_sys_call_table[SYS_ioperm] = (unsigned int)old_ioperm;
	my_sys_call_table[SYS_iopl] = (unsigned int)old_iopl;
	my_sys_call_table[SYS_ptrace] = (unsigned int)old_ptrace;
	my_sys_call_table[SYS_execve] = (unsigned int)old_execve;
	my_sys_call_table[SYS_quotactl] = (unsigned int)old_quotactl;
	my_sys_call_table[SYS_mknod] = (unsigned int)old_mknod;
	my_sys_call_table[SYS_rmdir] = (unsigned int)old_rmdir;
	my_sys_call_table[SYS_rename] = (unsigned int)old_rename;
	my_sys_call_table[SYS_uselib] = (unsigned int)old_uselib;
	my_sys_call_table[SYS_truncate] = (unsigned int)old_truncate;
	my_sys_call_table[SYS_truncate64] = (unsigned int)old_truncate64;
	my_sys_call_table[SYS_utime] = (unsigned int)old_utime;
	//my_sys_call_table[SYS_utimes] = (unsigned int)old_utimes;
	my_sys_call_table[SYS_chdir] = (unsigned int)old_chdir;
	my_sys_call_table[SYS_chroot] = (unsigned int)old_chroot;
	my_sys_call_table[SYS_chmod] = (unsigned int)old_chmod;
	my_sys_call_table[SYS_fchmod] = (unsigned int)old_fchmod;
	my_sys_call_table[SYS_chown] = (unsigned int)old_chown;
	my_sys_call_table[SYS_fchown] = (unsigned int)old_fchown;
	my_sys_call_table[SYS_lchown] = (unsigned int)old_lchown;
	my_sys_call_table[SYS_swapoff] = (unsigned int)old_swapoff;
	my_sys_call_table[SYS_swapon] = (unsigned int)old_swapon;
	my_sys_call_table[SYS_syslog] = (unsigned int)old_syslog;
	my_sys_call_table[SYS_creat] = (unsigned int)old_creat;
	my_sys_call_table[SYS_mkdir] = (unsigned int)old_mkdir;
	my_sys_call_table[SYS_acct] = (unsigned int)old_acct;
	my_sys_call_table[SYS_setrlimit] = (unsigned int)old_setrlimit;
	// my_sys_call_table[SYS_bind] = (unsigned int)old_bind;
	my_sys_call_table[SYS_nfsservctl] = (unsigned int)old_nfsservctl;
	my_sys_call_table[SYS_pivot_root] = (unsigned int)old_pivot_root;
	my_sys_call_table[SYS_ioctl] = (unsigned int)old_ioctl;
	my_sys_call_table[SYS_setpriority] = (unsigned int)old_setpriority;
	my_sys_call_table[SYS_setpgid] = (unsigned int)old_setpgid;
	my_sys_call_table[SYS_setgroups] = (unsigned int)old_setgroups;
	//my_sys_call_table[SYS_newuname] = (unsigned int)old_newuname;
	my_sys_call_table[SYS_sethostname] = (unsigned int)old_sethostname;
	my_sys_call_table[SYS_setdomainname] = (unsigned int)old_setdomainname;
	my_sys_call_table[SYS_nice] = (unsigned int)old_nice;
	//my_sys_call_table[SYS_sysctl] = (unsigned int)old_sysctl;
	//my_sys_call_table[SYS_pciconfig_write] = (unsigned int)old_pciconfig_write;
	my_sys_call_table[SYS_kill] = (unsigned int)old_kill;
	// my_sys_call_table[SYS_fchdir] = (unsigned int)old_fchdir;
	my_sys_call_table[SYS_socketcall] = (unsigned int)old_socketcall;

	// unregister the driver 

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
