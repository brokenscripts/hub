/*
Following video: Module 2-2: Exit shellcode
Using code from NASM\2-2

31 c0         xor    eax,eax
b0 01         mov    al,0x1
31 db         xor    ebx,ebx
b3 0a         mov    bl,0xa
cd 80         int    0x80
*/


unsigned char shellcode[] = {
"\x31\xc0\xb0\x01\x31\xdb\xb3\x0a\xcd\x80"
};

unsigned int shellcode_len = sizeof(shellcode)-1;