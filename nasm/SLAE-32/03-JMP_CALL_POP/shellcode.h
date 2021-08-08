/*
Following video: Module 2-3: JMP_CALL_POP
Using code from NASM\2-3

    Hello_jmp_call_pop:     file format elf32-i386

    Disassembly of section .text:

    08049000 <_start>:
    8049000:       eb 17                   jmp    8049019 <call_shellcode>

    08049002 <shellcode>:
    8049002:       31 c0                   xor    eax,eax
    8049004:       b0 04                   mov    al,0x4
    8049006:       31 db                   xor    ebx,ebx
    8049008:       b3 01                   mov    bl,0x1
    804900a:       59                      pop    ecx
    804900b:       31 d2                   xor    edx,edx
    804900d:       b2 0d                   mov    dl,0xd
    804900f:       cd 80                   int    0x80
    8049011:       31 c0                   xor    eax,eax
    8049013:       b0 01                   mov    al,0x1
    8049015:       31 db                   xor    ebx,ebx
    8049017:       cd 80                   int    0x80

    08049019 <call_shellcode>:
    8049019:       e8 e4 ff ff ff          call   8049002 <shellcode>

    0804901e <message>:
    804901e:       48                      dec    eax
    804901f:       65 6c                   gs ins BYTE PTR es:[edi],dx
    8049021:       6c                      ins    BYTE PTR es:[edi],dx
    8049022:       6f                      outs   dx,DWORD PTR ds:[esi]
    8049023:       20 57 6f                and    BYTE PTR [edi+0x6f],dl
    8049026:       72 6c                   jb     8049094 <message+0x76>
    8049028:       64 21 0a                and    DWORD PTR fs:[edx],ecx

*/


unsigned char shellcode[] = {
"\xeb\x17\x31\xc0\xb0\x04\x31\xdb\xb3\x01\x59\x31\xd2\xb2\x0d"
"\xcd\x80\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xe4\xff\xff\xff"
"\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\x0a"
};

unsigned int shellcode_len = sizeof(shellcode)-1;