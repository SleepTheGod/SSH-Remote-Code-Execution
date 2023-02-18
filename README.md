| # SSH Remote Code Execution |
| SSH Zero-Day | Made By ClumsyLulz | Taylor Christian Newsome |
Summary: 
The code provided is a C program that receives input parameters and generates a packet to be sent to a server via the SSH protocol. The program creates a buffer to store data to be sent, and then writes it to a file. It then creates a command line string to execute an SSH connection to the specified host and port, using the "system" function.
Issues:
There are several issues with the code that have been identified:
The program contains a buffer overflow vulnerability in the malloc function where only 28 bytes are allocated for the buffer, but 29 bytes are written to it. This can lead to memory corruption or a segmentation fault.
The return address calculation is incorrect. The program is using the value of the packet length instead of the buffer size to determine the return address, resulting in an incorrect value.
The format string in the printf statement for the return address is incorrect, resulting in an undefined behavior.
The program does not check the return value of the "open" and "write" functions, which can lead to data loss or failure to write the buffer to the file.
The program does not free the memory allocated for the "buffer" and "ssh" pointers, which can lead to memory leaks.
The program uses the "system" function to execute the SSH command, which can lead to security vulnerabilities, as it allows arbitrary commands to be executed with elevated privileges.
Recommendations:
To address the issues outlined above, the following recommendations are proposed:
Increase the size of the buffer allocation to 29 bytes to avoid buffer overflow issues.
Correct the return address calculation by using the buffer size instead of the packet length.
Correct the format string in the printf statement for the return address.
Check the return values of the "open" and "write" functions, and handle errors appropriately.
Free the memory allocated for the "buffer" and "ssh" pointers.
Replace the "system" function with a safer alternative, such as "execvp", to avoid potential security vulnerabilities.
It is recommended that these changes be made to the program to ensure its stability and security.

Added (with ChatGPT) ssh.c
compile it on ubuntu with
```
sudo apt-get install libbsd-dev
gcc ssh.c -o ssh -lbsd
```
There is a bad indexing in the code ssh.c (plz help !) no work yet :(
