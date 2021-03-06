# Introduction

Thanks for downloading Stik's Security Module for Linux.  The goal of
the project was to produce a syscall wrapper which implemented a
rudimentary labeling schema for system subject and objects.

# Support

The module should support the 2.4.x kernel line.  I've been working with
2.4.18 w/ slackware on one box and rh8 stock system on another.

Also, this only supports IPv4 - crazy things might happen with other
networking protocols.

# Building the module

In the `module/` directory just make.  You need to have a copy of your
kernel source in `/usr/src/linux` with the asm directories pointing to
the ia-32 architecture directories (`make config` should do that for you).

To make the utilities, in the `utils/` directory, check out the
makefile.  The makefile kinda sucks so you might have to do some
tweaking or hand building.

# Using the module

1st you need to make the interface to the module with `mknod`.  The
Utils and the module are hard coded to work with the following:

    mknod /dev/westsides c 40 0

Next make sure to have a `/etc/westsides/Label` file for the utilities
(see `utils/SampleLabel` for an example.)  Then just `insmod stiksec.o`
and you're up and going.

There's three distinct security policies to keep in mind:

1. Processes - once protected, always protected.  Labels carry across
   forks and execs.  Also, privileges are allowed unless specifically
   denied.

2. Filesystem - default policy is to block access only to files
   protected by a label by setting the label and the rwxd flags on a
   file.  To flip this policy for a type of access, you need to set the
   access bit on the process label.

3. Network - If you set a label, access is blocked for that label.  By
   specifying addr's and ports, you essentially punch holes in the
   network blocking.  The reverse policy is turned on by setting the
   `LABEL_FUNCTION` flag in the process label.

# Userland functions (utils/):

Note on human readable labels: The binary to hr table is coded to be
`/etc/westsides/Label`.  See `utils/SampleLabel` for an example.

protfile -
	protect a file.  use -r -w -x -d to block read write exec and
	delete respectively.  -l <num> sets the label number (just a
	number for now - until hrtob userspace translation functions are
	put in).  End with the file you want to protect.  Make sure you
	have spaces between and individually delimit each option due to
	bad programming.

delfilesec -
	specify a label with -l.  This function removes the particular
	label protection for the file

protexec - 
	launch a program with a label. -l <num> sets the label.
	-p <num> sets the privilege restrictions.  Take a look at
	module/privileges.h to see whats available and and 'em together.
	End with the program you want to exec.  Remember labeled
	processes can't access the module.

protnet -
	unblock access to a network resource. -raddr remote address
	-l addr local address.  use 1.2.3.4/5.6.7.8 if you need to do
	subnets.  -rport remote port  -lport localport.  use 10/20 to do
	a range from 10 to 20.  -L <num> sets a label.  networking is
	unblocked until you use protnet to set a label.  if you want to
	block all networking for a label, just use protnet -L <label>,
	without specifying any addr or port.

delnetsec -
	same args, opposite result

getfilesec -
	Takes no args.  Dumps a big block of the protected files back to
	you.  Segfaults if you have too many protected files.

getnetsec -
	see getfilesec

getpidsec -
	Takes a PID and returns the label and privilege information

loadtemplate -
	Loads a file and network security template.  See
	utils/SampleTemplate for an example.

# Shortcomings

* Security model isn't proven.
* All syscalls haven't been tested.
* IPC's aren't controlled.
* Not optimized.

# Other information

## Label format

    Read  Write  Execute  Append  Delete  Create  Function  Recurse  Label
    1     2      3        4       5       6       7         8        9-32

## Network attr format

    Local addr	Local mask	Local port	Range
    1-32		33-64		65-80		81-96
    Remote addr	Remote mask	Remote port	Range
    97-128		129-160		161-176		177-192

Have fun!!!

-Stik
