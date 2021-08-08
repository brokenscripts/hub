# JMP_CALL_POP

## NASM

### HELLO WORLD
```nasm
; HelloWorld-Shellcode.nasm
; SLAE32
; JMP CALL POP method, no NULL

global _start

section .text
_start: 
    jmp short call_shellcode


shellcode:
    ; Print Hello World on Screen
    xor eax, eax
    mov al, 0x4
    
    xor ebx, ebx
    mov bl, 0x1
    
    pop ecx             ; Pop the address of message from the stack into ECX

    xor edx, edx
    mov dl, 13          ; 13 decimal == Message Length

    int 0x80

    ; Exit gracefully
    xor eax, eax
    mov al, 0x1         ; exit()
    
    xor ebx, ebx        ; return code of 0
    
    int 0x80            ; syscall for exit(0)

call_shellcode:
    call shellcode
    message: db "Hello World!", 0xA      ; 0xA == Newline in ASCII
```

---

## Convert to Shellcode

Use the [compile.sh](../compile.sh) script that will automatically compile, assemble, link, and then print the shellcode for CPP consumption.  

---

## CPP

### Header file (.h)  
```cpp
/*
Following video: Module 2-3: JMP_CALL_POP

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