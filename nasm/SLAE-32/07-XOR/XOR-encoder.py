#!/usr/bin/python3

# Python3 XOR Encoder
# SLAE32

shellcode = (
# Place shellcode here
b"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
)

encoded = ""
encoded2 = ""

print ("Encoded shellcode with XOR 0xAA...\n")

for x in shellcode:
    # XOR Encoding
    y = x^0xAA
    encoded += "\\x"
    encoded += "%02x" % y

    encoded2 += "0x"
    encoded2 += "%02x," % y

print(encoded)
print()
print(encoded2)
print()

print("Length: %d" % len(shellcode))