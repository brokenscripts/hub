/*
Following video: Module 2-4: STACK
Using code from NASM\2-4

    2-4_STACK/Hello_stack:     file format elf32-i386
    
    Disassembly of section .text:
    
    08049000 <_start>:
     8049000:       31 c0                   xor    eax,eax
     8049002:       b0 04                   mov    al,0x4
     8049004:       31 db                   xor    ebx,ebx
     8049006:       b3 01                   mov    bl,0x1
     8049008:       31 d2                   xor    edx,edx
     804900a:       52                      push   edx
     804900b:       68 72 6c 64 0a          push   0xa646c72
     8049010:       68 6f 20 57 6f          push   0x6f57206f
     8049015:       68 48 65 6c 6c          push   0x6c6c6548
     804901a:       89 e1                   mov    ecx,esp
     804901c:       b2 0c                   mov    dl,0xc
     804901e:       cd 80                   int    0x80
     8049020:       31 c0                   xor    eax,eax
     8049022:       b0 01                   mov    al,0x1
     8049024:       31 db                   xor    ebx,ebx
     8049026:       cd 80                   int    0x80
*/


unsigned char shellcode[] = {
"\x31\xc0\xb0\x04\x31\xdb\xb3\x01\x31\xd2\x52\x68\x72\x6c\x64\x0a\x68\x6f\x20\x57\x6f\x68\x48\x65\x6c\x6c\x89\xe1\xb2\x0c\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80"
};

unsigned int shellcode_len = sizeof(shellcode)-1;