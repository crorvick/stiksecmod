/*
Stik's Security Module
privilege.h - header for privilege related defines
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

#ifndef WESTSIDES_PRIVILEGE
#define WESTSIDES_PRIVILEGE
#endif

// restrict  doe  dou

// 0x1 0x2 0x4
#define PRIVILEGE_SETID 0x7

// 0x8 0x10 0x20
#define PRIVILEGE_MODULE 0x38
#define PRIVILEGE_MKNOD 0x38
#define PRIVILEGE_SYSCTL 0x38

// 0x40 0x80 0x100
#define PRIVILEGE_PCICONFIG 0x1c0
#define PRIVILEGE_RAWIO 0x1c0

// 0x200 0x400 0x800
#define PRIVILEGE_REBOOT 0xe00
#define PRIVILEGE_SIGNAL 0xe00

// 0x1000 0x2000 0x4000
#define PRIVILEGE_NICE 0x7000
#define PRIVILEGE_RLIMIT 0x7000
#define PRIVILEGE_FSQUOTA 0x7000

// 0x8000 0x10000 0x20000
#define PRIVILEGE_NAME 0x38000
#define PRIVILEGE_TIME 0x38000

// 0x40000 0x80000 0x100000
#define PRIVILEGE_IOCTL 0x1c0000

// 0x200000 0x400000 0x800000
#define PRIVILEGE_FILESYSTEM 0xe00000

// 0x1000000 0x2000000 0x4000000
#define PRIVILEGE_SWAP 0x7000000
#define PRIVILEGE_ACCT 0x7000000
#define PRIVILEGE_SYSLOG 0x7000000

// 0x8000000 0x10000000 0x20000000
#define PRIVILEGE_MOUNT 0x38000000
#define PRIVILEGE_NFSCTL 0x38000000

#define PRIVILEGE_MASK 0x9249249
#define DOE_MASK 0x12492492
#define DOU_MASK 0x24924924

