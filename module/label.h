/*
Stik's Security Module
label.h - label related defines
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

#ifndef WESTSIDES_LABEL
#define WESTSIDES_LABEL
#endif

#define LABEL_READ	0x1
#define LABEL_WRITE	0x2
#define LABEL_EXEC	0x4
#define LABEL_APPEND	0x8
#define LABEL_DELETE	0x10
#define LABEL_CREATE	0x20
#define LABEL_FUNCTION	0x40
#define LABEL_RECURSE	0x80
#define LABEL_MASK	0xffffff00 
