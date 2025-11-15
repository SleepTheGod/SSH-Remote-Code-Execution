# SSH Remote Code Execution

**SSH Zero-Day** | Made by ClumsyLulz & Taylor Christian Newsome

## Summary

This repository contains a C program that accepts input parameters and generates a packet to be sent to a server over the SSH protocol. The program allocates a buffer to hold the data, writes it to a file, and constructs a command-line string to initiate an SSH connection to a specified host and port using the `system` function.

## Identified Issues

Several security and stability issues exist in the current implementation:

1. **Buffer Overflow**: Only 28 bytes are allocated with `malloc`, but 29 bytes are written, which can cause memory corruption or segmentation faults.
2. **Incorrect Return Address Calculation**: The return address is computed using the packet length rather than the buffer size, resulting in an invalid value.
3. **Format String Issue**: The `printf` statement for the return address contains an incorrect format string, leading to undefined behavior.
4. **Unchecked I/O Operations**: The return values of `open` and `write` are not verified, risking data loss or incomplete writes.
5. **Memory Leaks**: Allocated memory for `buffer` and `ssh` pointers is never freed.
6. **Unsafe Command Execution**: Using `system` to execute the SSH command allows arbitrary commands to run with elevated privileges, posing a serious security risk.

## Recommendations

To improve the program's security and reliability, the following changes are recommended:

* Allocate at least 29 bytes for the buffer to prevent overflow.
* Use the buffer size, not the packet length, when calculating the return address.
* Correct the format string in the `printf` statement for the return address.
* Check and handle return values for `open` and `write` calls.
* Free all dynamically allocated memory for `buffer` and `ssh` pointers.
* Replace `system` with a safer alternative like `execvp` to avoid executing arbitrary commands.

Implementing these fixes will enhance the program’s stability and reduce potential security vulnerabilities.

---
```bash

root@29bcb37807cf:/poc# apt-get install -y --allow-unauthenticated libc6-dev libgcc1 libstdc++6
Reading package lists... Done
Building dependency tree
Reading state information... Done
libgcc1 is already the newest version.
libgcc1 set to manually installed.
libstdc++6 is already the newest version.
libstdc++6 set to manually installed.
libc6-dev is already the newest version.
0 upgraded, 0 newly installed, 0 to remove and 15 not upgraded.
root@29bcb37807cf:/poc# apt-get install -y --allow-unauthenticated gcc g++ make dpkg-dev
Reading package lists... Done
Building dependency tree
Reading state information... Done
dpkg-dev is already the newest version.
g++ is already the newest version.
gcc is already the newest version.
make is already the newest version.
0 upgraded, 0 newly installed, 0 to remove and 15 not upgraded.
root@29bcb37807cf:/poc# apt-get install -y --allow-unauthenticated build-essential
Reading package lists... Done
Building dependency tree
Reading state information... Done
build-essential is already the newest version.
0 upgraded, 0 newly installed, 0 to remove and 15 not upgraded.
root@29bcb37807cf:/poc# apt-get update -o Acquire::Check-Valid-Until=false && \
> apt-get install -y --allow-unauthenticated libc6-dev libgcc1 libstdc++6 gcc g++ make dpkg-dev build-essential
Get:1 http://archive.debian.org wheezy Release.gpg [2373 B]
Get:2 http://archive.debian.org wheezy/updates Release.gpg [1601 B]
Hit http://archive.debian.org wheezy Release
Hit http://archive.debian.org wheezy/updates Release
Ign http://archive.debian.org wheezy Release
Hit http://archive.debian.org wheezy/main i386 Packages
Ign http://archive.debian.org wheezy/updates Release
Hit http://archive.debian.org wheezy/contrib i386 Packages
Hit http://archive.debian.org wheezy/non-free i386 Packages
Hit http://archive.debian.org wheezy/updates/main i386 Packages
Hit http://archive.debian.org wheezy/updates/contrib i386 Packages
Hit http://archive.debian.org wheezy/updates/non-free i386 Packages
Fetched 3974 B in 1s (3086 B/s)
Reading package lists... Done
W: GPG error: http://archive.debian.org wheezy Release: The following signatures were invalid: KEYEXPIRED 1587841717 KEYEXPIRED 1668891673 KEYEXPIRED 1557241909
W: GPG error: http://archive.debian.org wheezy/updates Release: The following signatures were invalid: KEYEXPIRED 1668892417 KEYEXPIRED 1587841717
Reading package lists... Done
Building dependency tree
Reading state information... Done
build-essential is already the newest version.
dpkg-dev is already the newest version.
libgcc1 is already the newest version.
libstdc++6 is already the newest version.
g++ is already the newest version.
gcc is already the newest version.
make is already the newest version.
libc6-dev is already the newest version.
0 upgraded, 0 newly installed, 0 to remove and 15 not upgraded.
root@29bcb37807cf:/poc# which gcc
/usr/bin/gcc
root@29bcb37807cf:/poc# which g++
/usr/bin/g++
root@29bcb37807cf:/poc# which make
/usr/bin/make
root@29bcb37807cf:/poc# apt-get update -o Acquire::Check-Valid-Until=false
Get:1 http://archive.debian.org wheezy Release.gpg [2373 B]
Get:2 http://archive.debian.org wheezy/updates Release.gpg [1601 B]
Hit http://archive.debian.org wheezy Release
Hit http://archive.debian.org wheezy/updates Release
Ign http://archive.debian.org wheezy Release
Ign http://archive.debian.org wheezy/updates Release
Hit http://archive.debian.org wheezy/main i386 Packages
Hit http://archive.debian.org wheezy/contrib i386 Packages
Hit http://archive.debian.org wheezy/non-free i386 Packages
Hit http://archive.debian.org wheezy/updates/main i386 Packages
Hit http://archive.debian.org wheezy/updates/contrib i386 Packages
Hit http://archive.debian.org wheezy/updates/non-free i386 Packages
Fetched 3974 B in 1s (2983 B/s)
Reading package lists... Done
W: GPG error: http://archive.debian.org wheezy Release: The following signatures were invalid: KEYEXPIRED 1587841717 KEYEXPIRED 1668891673 KEYEXPIRED 1557241909
W: GPG error: http://archive.debian.org wheezy/updates Release: The following signatures were invalid: KEYEXPIRED 1668892417 KEYEXPIRED 1587841717
root@29bcb37807cf:/poc# apt-get install -y --allow-unauthenticated gcc g++ make libc6-dev dpkg-dev
Reading package lists... Done
Building dependency tree
Reading state information... Done
dpkg-dev is already the newest version.
g++ is already the newest version.
gcc is already the newest version.
make is already the newest version.
libc6-dev is already the newest version.
0 upgraded, 0 newly installed, 0 to remove and 15 not upgraded.
root@29bcb37807cf:/poc# apt-get install -y --allow-unauthenticated build-essential
Reading package lists... Done
Building dependency tree
Reading state information... Done
build-essential is already the newest version.
0 upgraded, 0 newly installed, 0 to remove and 15 not upgraded.
root@29bcb37807cf:/poc# gcc --version
gcc (Debian 4.7.2-5) 4.7.2
Copyright (C) 2012 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

root@29bcb37807cf:/poc# g++ --version
g++ (Debian 4.7.2-5) 4.7.2
Copyright (C) 2012 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

root@29bcb37807cf:/poc# make --version
GNU Make 3.81
Copyright (C) 2006  Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.

This program built for i486-pc-linux-gnu
root@29bcb37807cf:/poc# ./poc
bash: ./poc: No such file or directory
root@29bcb37807cf:/poc# ls
Exploit.c  Exploit.cpp  Exploit.out  LICENSE  README.md
root@29bcb37807cf:/poc# make
make: *** No targets specified and no makefile found.  Stop.
root@29bcb37807cf:/poc# make Exploit.c
make: Nothing to be done for `Exploit.c'.
root@29bcb37807cf:/poc# gcc Exploit.c -o exploit
root@29bcb37807cf:/poc# g++ Exploit.cpp -o exploit
root@29bcb37807cf:/poc# ./exploit

Usage: ./exploit <saved eip> <count> <packet length> <username length> <host> <port> <h(i)>

root@29bcb37807cf:/poc# cat > Makefile <<'EOF'
> all:
> \tg++ Exploit.cpp -o exploit
> EOF
root@29bcb37807cf:/poc# make
Makefile:2: *** missing separator.  Stop.
root@29bcb37807cf:/poc# cat > Makefile <<'EOF'
> all:
> g++ Exploit.cpp -o exploit
> EOF
root@29bcb37807cf:/poc# make
Makefile:2: *** missing separator.  Stop.
root@29bcb37807cf:/poc# g++ Exploit.cpp -o exploit
root@29bcb37807cf:/poc# ./exploit

Usage: ./exploit <saved eip> <count> <packet length> <username length> <host> <port> <h(i)>

root@29bcb37807cf:/poc# ./exploit 0 1 256 8 127.0.0.1 22 0

Saved Eip: &h + 1543007393
Return Address: 0x811
Packet Length: 264
Username Length: 8

./ssh -p 22 -v -l root 127.0.0.1
sh: 1: ./ssh: not found
root@29bcb37807cf:/poc#
root@29bcb37807cf:/poc# sudo
usage: sudo [-D level] -h | -K | -k | -V
usage: sudo -v [-AknS] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid]
usage: sudo -l[l] [-AknS] [-D level] [-g groupname|#gid] [-p prompt] [-U user name] [-u user name|#uid] [-g groupname|#gid] [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid] [-g groupname|#gid] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] [-u user name|#uid] file ...
root@29bcb37807cf:/poc# passwd
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
root@29bcb37807cf:/poc#
```
