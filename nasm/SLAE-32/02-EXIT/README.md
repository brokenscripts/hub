# EXIT

## NASM

### WITH NULLS
This uses `syscall` to force an exit, but leaves `NULL` chars when created
```nasm
; Filename: exit_with_nulls.nasm
; From SLAE32

global _start:

section .text
_start:
    mov eax, 1          ; exit()
    mov ebx, 10         ; status code for exit()
    int 0x80            ; syscall
```

Result, using `objdump`:
```shell
objdump -d -M intel exit_with_nulls.nasm
```

```nasm
; Filename: exit_with_nulls.nasm

; exit_with_nulls:     file format elf32-i386   

Disassembly of section .text:
08049000 <_start>:
 8049000:       b8 01 00 00 00          mov    eax,0x1
 8049005:       bb 0a 00 00 00          mov    ebx,0xa
 804900a:       cd 80                   int    0x80
```

### WITHOUT NULLS
This uses `syscall` to force an exit, ensuring that no `NULL` chars exist.

```nasm
; Filename: exit_no_nulls.nasm
; From SLAE32

global _start:

section .text
_start:
    xor eax, eax        ; Zero out EAX
    mov al, 1           ; Lower half of EAX register
    xor ebx, ebx        ; Zero out EBX
    mov bl, 10          ; Lower half of EBX register
    int 0x80
```

Result, using `objdump`:  
```shell
objdump -d -M intel exit_no_nulls.nasm
```

```nasm
; Filename: exit_no_nulls.nasm
;
; exit_no_nulls:     file format elf32-i386

Disassembly of section .text:

08049000 <_start>:
 8049000:       31 c0                   xor    eax,eax
 8049002:       b0 01                   mov    al,0x1
 8049004:       31 db                   xor    ebx,ebx
 8049006:       b3 0a                   mov    bl,0xa (10)      ; This instruction is optional, can be removed since exit doesn't NEED to return 10
 8049008:       cd 80                   int    0x80
```

---

## Convert to Shellcode

Use the [compile.sh](../compile.sh) script that will automatically compile, assemble, link, and then print the shellcode for CPP consumption.  

---

## CPP  

### Header file (.h)  
Using the `objdump` command above, place the shellcode in a convenient header file.  
```cpp
/*
Following video: Module 2-2: Exit shellcode

31 c0         xor    eax,eax
b0 01         mov    al,0x1
31 db         xor    ebx,ebx
b3 0a         mov    bl,0xa
cd 80         int    0x80
*/


unsigned char shellcode[] = {
"\x31\xc0\xb0\x01\x31\xdb\xb3\x0a\xcd\x80"
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