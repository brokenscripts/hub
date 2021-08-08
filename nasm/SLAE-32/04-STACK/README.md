# STACK

## PYTHON (PREP)  
In order to get the "Hello World" string to print in hex and properly reversed to `PUSH` on the stack, use the following snippet:  
```python
python3 -c 'code=b"Hello World\n"; print(code[::-1].hex())'

0a646c726f57206f6c6c6548
```

Alternatively, use the following script:  
```python
#!/usr/bin/python3

import sys
input = sys.argv[1].encode()


print("String length: " + str(len(input)))

stringList = [input[i:i+4] for i in range(0, len(input), 4)]

for item in stringList[::-1]:
    print(item[::-1].decode() + " : " + item[::-1].hex())
```

Invoke it as follows:  
```python
python3 string_reverse.py "Hello World"
String length: 11
dlr : 646c72
oW o : 6f57206f
lleH : 6c6c6548

# Manually append 0x0a to after Hello World for the new line and to make the string length == 12
```

## NASM  

### HELLO WORLD  
```nasm
; HelloWorld-Stack.nasm
; SLAE32
; Stack

global _start

section .text
_start: 
    ; Print Hello World on Screen
    xor eax, eax
    mov al, 0x4
    
    xor ebx, ebx
    mov bl, 0x1

    xor edx, edx
    push edx            ; Push 4x NULLs on stack (0x00000000)
    push 0x0a646c72     ; \ndlr
    push 0x6f57206f     ; oW o
    push 0x6c6c6548     ; lleH

    mov ecx, esp        ; Move stack location into ECX

    mov dl, 12          ; 12 decimal == Message Length

    int 0x80

    ; Exit gracefully
    xor eax, eax
    mov al, 0x1
    
    xor ebx, ebx
    
    int 0x80
```


---


## Convert to Shellcode  

Use the [compile.sh](../compile.sh) script that will automatically compile, assemble, link, and then print the shellcode for CPP consumption.  


---


## CPP  
### Header file (.h)  
```cpp
/*
Following video: Module 2-4: STACK

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