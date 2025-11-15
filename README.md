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
root@vmi2865841:~/tools/SSH-Remote-Code-Execution# cat /etc/issue
Debian GNU/Linux 12 \n \l

root@vmi2865841:~/tools/SSH-Remote-Code-Execution# docker run -it --rm \
>   -v /root/tools/SSH-Remote-Code-Execution:/poc \
>   i386/debian:wheezy bash
root@29bcb37807cf:/# cat /etc/issue
Debian GNU/Linux 7 \n \l

root@29bcb37807cf:/# cat /etc/shadow
root:*:17955:0:99999:7:::
daemon:*:17955:0:99999:7:::
bin:*:17955:0:99999:7:::
sys:*:17955:0:99999:7:::
sync:*:17955:0:99999:7:::
games:*:17955:0:99999:7:::
man:*:17955:0:99999:7:::
lp:*:17955:0:99999:7:::
mail:*:17955:0:99999:7:::
news:*:17955:0:99999:7:::
uucp:*:17955:0:99999:7:::
proxy:*:17955:0:99999:7:::
www-data:*:17955:0:99999:7:::
backup:*:17955:0:99999:7:::
list:*:17955:0:99999:7:::
irc:*:17955:0:99999:7:::
gnats:*:17955:0:99999:7:::
nobody:*:17955:0:99999:7:::
libuuid:!:17955:0:99999:7:::
root@29bcb37807cf:/# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
root@29bcb37807cf:/# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0@if11: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP
    link/ether 1e:13:2e:66:6f:69 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
root@29bcb37807cf:/# cd /bin/
root@29bcb37807cf:/bin# ls
bash   chmod  dash  df     dnsdomainname  egrep  findmnt  gzexe     ip     ls     mknod   mount       nisdomainname  ping6  readlink  run-parts  sh.distrib  stty  tailf     touch   uname       which         zcmp    zfgrep  zless
cat    chown  date  dir    domainname     false  grep     gzip      ln     lsblk  mktemp  mountpoint  pidof          pwd    rm        sed        sleep       su    tar       true    uncompress  ypdomainname  zdiff   zforce  zmore
chgrp  cp     dd    dmesg  echo           fgrep  gunzip   hostname  login  mkdir  more    mv          ping           rbash  rmdir     sh         ss          sync  tempfile  umount  vdir        zcat          zegrep  zgrep   znew
root@29bcb37807cf:/bin# df -h
Filesystem      Size  Used Avail Use% Mounted on
overlay         1.4T  977G  346G  74% /
tmpfs            64M     0   64M   0% /dev
shm              64M     0   64M   0% /dev/shm
/dev/sda1       1.4T  977G  346G  74% /poc
/dev/sda1       1.4T  977G  346G  74% /etc/resolv.conf
/dev/sda1       1.4T  977G  346G  74% /etc/hostname
/dev/sda1       1.4T  977G  346G  74% /etc/hosts
tmpfs            48G     0   48G   0% /proc/acpi
tmpfs            64M     0   64M   0% /proc/interrupts
tmpfs            64M     0   64M   0% /proc/kcore
tmpfs            64M     0   64M   0% /proc/keys
tmpfs            64M     0   64M   0% /proc/timer_list
tmpfs            48G     0   48G   0% /sys/firmware
root@29bcb37807cf:/bin# cat /proc/keys
root@29bcb37807cf:/bin# cat /etc/resolv.conf
# Generated by Docker Engine.
# This file can be edited; Docker Engine will not make further changes once it
# has been modified.

nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 213.136.95.10
nameserver 213.136.95.11
search .

# Based on host file: '/etc/resolv.conf' (legacy)
# Overrides: []
root@29bcb37807cf:/bin# cut -d: -f1 /etc/passwd | while read u; do printf '%s:root\n' "$u"; done | chpasswd
root@29bcb37807cf:/bin# cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
root@29bcb37807cf:/bin# ls
bash   chmod  dash  df     dnsdomainname  egrep  findmnt  gzexe     ip     ls     mknod   mount       nisdomainname  ping6  readlink  run-parts  sh.distrib  stty  tailf     touch   uname       which         zcmp    zfgrep  zless
cat    chown  date  dir    domainname     false  grep     gzip      ln     lsblk  mktemp  mountpoint  pidof          pwd    rm        sed        sleep       su    tar       true    uncompress  ypdomainname  zdiff   zforce  zmore
chgrp  cp     dd    dmesg  echo           fgrep  gunzip   hostname  login  mkdir  more    mv          ping           rbash  rmdir     sh         ss          sync  tempfile  umount  vdir        zcat          zegrep  zgrep   znew
root@29bcb37807cf:/bin# false
root@29bcb37807cf:/bin# fgrep
Usage: fgrep [OPTION]... PATTERN [FILE]...
Try 'fgrep --help' for more information.
root@29bcb37807cf:/bin# mount
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/JSZILXAM2W5WJUFED2A2ECQT5C:/var/lib/docker/overlay2/l/CJF3YAZDOI6XVZQU2XTOQIAGE6,upperdir=/var/lib/docker/overlay2/62f4d739148336cedad11a87ffe8d5616ab8bcbbeac96acd46b155e3e395ed12/diff,workdir=/var/lib/docker/overlay2/62f4d739148336cedad11a87ffe8d5616ab8bcbbeac96acd46b155e3e395ed12/work)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev type tmpfs (rw,nosuid,size=65536k,mode=755,inode64)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cgroup on /sys/fs/cgroup type cgroup2 (ro,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=65536k,inode64)
/dev/sda1 on /poc type ext4 (rw,relatime,discard,errors=remount-ro)
/dev/sda1 on /etc/resolv.conf type ext4 (rw,relatime,discard,errors=remount-ro)
/dev/sda1 on /etc/hostname type ext4 (rw,relatime,discard,errors=remount-ro)
/dev/sda1 on /etc/hosts type ext4 (rw,relatime,discard,errors=remount-ro)
devpts on /dev/console type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
proc on /proc/bus type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/fs type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/irq type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/sys type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/sysrq-trigger type proc (ro,nosuid,nodev,noexec,relatime)
tmpfs on /proc/acpi type tmpfs (ro,relatime,inode64)
tmpfs on /proc/interrupts type tmpfs (rw,nosuid,size=65536k,mode=755,inode64)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755,inode64)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755,inode64)
tmpfs on /proc/timer_list type tmpfs (rw,nosuid,size=65536k,mode=755,inode64)
tmpfs on /sys/firmware type tmpfs (ro,relatime,inode64)
root@29bcb37807cf:/bin#
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
