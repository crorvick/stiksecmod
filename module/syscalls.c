#include <linux/unistd.h>
#include <linux/sys.h>

void syshook(void);

// Since in the future we will so rudely be denied access to
// sys_call_table, we have to go ahead and find it
// This code is borrowed from sd and devik's article
// in Phrack 58
long *getSysCallTable(void)
{
	int ctr = 0;
        unsigned int sys_call_off;

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
                        return NULL;
                }
        }
        return (long *)*(unsigned int *)(sys_call_off + 3);
}

void saveSysCallTable(long *oldSysCallTable, long *savedSysCallTable)
{
	memcpy(savedSysCallTable, oldSysCallTable, sizeof(long) * NR_syscalls);
}

void restoreSysCallTable(long *savedSysCallTable, long *oldSysCallTable)
{
	memcpy(oldSysCallTable, savedSysCallTable, sizeof(long) * NR_syscalls);
}

void trapSysCalls(long *sysCallTable)
{
	int ctr;
	for (ctr = 0; ctr < NR_syscalls; ++ctr)
		sysCallTable[ctr] = (long)syshook;
}
