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
