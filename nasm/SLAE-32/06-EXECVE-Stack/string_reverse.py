#!/usr/bin/python3

import sys
input = sys.argv[1].encode()


print("String length: " + str(len(input)))

stringList = [input[i:i+4] for i in range(0, len(input), 4)]

for item in stringList[::-1]:
    print(item[::-1].decode() + " : " + item[::-1].hex())