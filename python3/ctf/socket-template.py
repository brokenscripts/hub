#!/usr/bin/python3
import socket
import re


# Global Constants
MAXBUF = 4096
KEYWORDS = 'flag FLAG'
HOST = '195.154.53.62'
PORT = 1337
timeout_val = 10  # seconds

# Shellcode placeholder
shellcode = (
b"\x90"
b"\x90"
)


if __name__ == '__main__':
    print('[*] creating the socket')
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout_val)

    client.connect(HOST, PORT)

    while True:
        data = b''

        # receive and store data
        while True:
            chunk = client.recv(MAXBUF)
            data += chunk
            if len(chunk) < MAXBUF:
                break

        # store decoded data for future usage
        decoded = data.decode('utf-8')

        # our flag contains words from KEYWORDS, once it's revealed print received data and exit
        if any(words in KEYWORDS for words in decoded):
            print(decoded)
            break

        # \d+ matches a digit (equal to [0-9])
        # .{3} matches any  character, except line terminators exactly three times
        match = re.search('\d+.{3}\d+', decoded)
        if not match:
            raise ValueError("Invalid expression string")

        expression = match.group(0)

        # properly handle division
        if '/' in expression:
            expression = expression.replace('/', '//')

        result = eval(expression)

        # print results to screen to see script progress
        print(expression + ' = ' + str(result))

        # encode and transfer
        output = str(result).encode('utf-8') + b'\n'
        client.send(output)
