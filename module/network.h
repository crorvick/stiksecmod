/*
Stik's Security Module
network.h - network related structures
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

#ifndef WESTSIDES_NET
#define WESTSIDES_NET
#endif 

typedef struct network_attribute
{
	unsigned long laddr;
	unsigned long lmask;
	unsigned short lport;
	unsigned short lrange;
	unsigned long raddr;	
	unsigned long rmask;
	unsigned short rport;
	unsigned short rrange;
} netAttr;

typedef struct network_pass_attribute
{
	unsigned long label;
	unsigned long laddr;
	unsigned long lmask;
	unsigned short lport;
	unsigned short lrange;
	unsigned long raddr;	
	unsigned long rmask;
	unsigned short rport;
	unsigned short rrange;
} netPassAttr;
