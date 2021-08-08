# SLAE-32

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [SLAE-32](#slae-32)
  - [Chapters](#chapters)
  - [NASM Compile script](#nasm-compile-script)
  - [CPP](#cpp)
    - [Header (shellcode) (.h)](#header-shellcode-h)
    - [CPP (function pointer) (.cpp)](#cpp-function-pointer-cpp)
    - [CPP (memory alloc) (.cpp)](#cpp-memory-alloc-cpp)
  - [Compilation (GCC)](#compilation-gcc)
    - [Compile (`x86`)](#compile-x86)
    - [DISABLE ALL PROTECTIONS](#disable-all-protections)
    - [Compile (`x64`)](#compile-x64)

<!-- /code_chunk_output -->


## Chapters
[02-Exit](./02-EXIT/README.md)  
[03-JMP_CALL_POP](./03-JMP_CALL_POP/README.md)  
[04-STACK](./04-STACK/README.md)  
[05-EXECVE-JMP_CALL_POP](./05-EXECVE-JMP_CALL_POP/README.md)  
[06-EXECVE-STACK](./06-EXECVE-STACK/README.md)  
[07-XOR](./07-XOR/README.md)  
[09-NOT](./09-NOT/README.md)  
[10-INSERT](./10-INSERT/README.md)  
[11-XOR-MMX](./11-XOR-MMX/README.md)  
[12-POLYMORPHISM](./12-POLYMORPHISM/README.md)  

---

## NASM Compile script
In order to have a consistent method of compiling, assembling, linking, and printing for SLAE-32, I modified the script shown in the videos to this:  
```shell
#!/bin/bash
# Base from SLAE32

echo '======================================'
echo '||            NASM & LD             ||'
echo -e '======================================\n'

full_filename="$(basename -- $1)"
extension=$([[ "$full_filename" = *.* ]] && echo ".${full_filename##*.}" || echo '')
filename="${full_filename%.*}"
fullpath="$(realpath $1)"
dirpath="${fullpath%/*}"

echo '[!] Attempting to compile' $full_filename 'into directory' $dirpath

echo '[+] Assembling with NASM...'
nasm -f elf32 -o $dirpath/$filename.o $dirpath/$filename.nasm &&

echo '[+] Linking 32-bit executable (i386)...'
ld -m elf_i386 -o $dirpath/$filename $dirpath/$filename.o &&
# ld -N -m elf_i386 -o $dirpath/$filename $dirpath/$filename.o &&   # -N to make .text & .data section WRITEABLE

echo -e '[+] nasm & ld Done!\n'

echo '======================================'
echo '||             OBJDUMP              ||'
echo -e '======================================\n'

objdump --insn-width=6 -d -M intel $dirpath/$filename &&

echo -e '\n[+] objdump Done!\n'

echo '======================================'
echo '||         Shellcode (Hex)           ||'
echo -e '======================================\n'

# Original method, one long string
# objdump --insn-width=6 -d $dirpath/$filename|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

# Cleaner method to print in 16-byte chunks (4*16)
objdump --insn-width=6 -d $dirpath/$filename|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|
paste -d '' -s | egrep -o '(.){1,64}' | sed 's/^/"/'|sed 's/$/"/g'

echo -n 'Shellcode length: '
objdump --insn-width=6 -d $dirpath/$filename|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|
paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' | grep -Eo '\\x[[:xdigit:]]{2}' | wc -l

# Quick test & output for NULLs
if test "$(
objdump --insn-width=6 -d $dirpath/$filename|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|
paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' | grep '\x00' | wc -l
)" -gt 0
then
    echo -e "\n[!] NULLs found! [!]\n"
fi

echo -e '\n[+] Hex display Done!\n'

# Pythonic method:
# for i in range(0, len(code), 10): 
#   print("".join("\\x%02x" % i for i in code[i:i+10]))
```

---

## CPP 
The same template files were used throughout.  The `cpp` file includes 2 methods of calling the shellcode.  
1) Function pointer  
2) Memory alloc  

### Header (shellcode) (.h)
```cpp
/*
OBJDUMP output goes here for reference
*/

unsigned char shellcode[] = {
// INSERT SHELLCODE HERE
};

unsigned int shellcode_len = sizeof(shellcode)-1;
```

### CPP (function pointer) (.cpp)
```cpp
#include <stdio.h>
#include <string.h>
#include <stdint.h>		// Requirement for intptr_t/uintptr_t

#include "shellcode.h"  // Clean place to keep all shellcode


int main()
{
	for (int i = 0; i < shellcode_len; i++){
		// printf("%02x ",*(shellcode + i));	// Output example: 31 c0 50 68
		printf("\\x%02x",*(shellcode + i));		// Output example: \x31\xc0\x50\x68
	}
	printf("\n");
	printf("Shellcode Length: %d\n", shellcode_len);


	// SLAE-32 method
	// Create a function pointer, that points to the raw shellcode, then call the shellcode pointer

	int (*shellcode_func_ptr)() = (int(*)())shellcode;
	mprotect((void*)((uintptr_t)shellcode & ~0xFFF), 8192, PROT_READ|PROT_WRITE|PROT_EXEC);	// Required to add this to make the PAGE the shellcode is in, executable
	printf("Shellcode address: %p\n", shellcode_func_ptr);
	shellcode_func_ptr();

	return 0;
}
```

### CPP (memory alloc) (.cpp)
```cpp
#include <stdio.h>
#include <string.h>
#include <stdint.h>		// Requirement for intptr_t/uintptr_t
// @ts-ignore
#include <sys/mman.h>	// Linux requirement for mmap / mprotect

#include "shellcode.h"  // Clean place to keep all shellcode


int main()
{
	for (int i = 0; i < shellcode_len; i++){
		// printf("%02x ",*(shellcode + i));	// Output example: 31 c0 50 68
		printf("\\x%02x",*(shellcode + i));		// Output example: \x31\xc0\x50\x68
	}
	printf("\n");
	printf("Shellcode Length: %d\n", shellcode_len);


	// Memory Alloc method

	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;

	void *shellcode_mem_alloc = mmap(0, shellcode_len, prot, flags, -1, 0);

	if(shellcode_mem_alloc == MAP_FAILED)
	{
		perror("mmap");
		return 1;	// Error'd out
	}
	else{
		memcpy(shellcode_mem_alloc, shellcode, shellcode_len);
		((void(*)())shellcode_mem_alloc)();
	}


	return 0;
}
```

---


## Compilation (GCC)  
The following commands will produce a compiled binary named `shellcode` using the `cpp` file `linux-shellcode-func_ptr.cpp`

### Compile (`x86`)  
_Note: Requires package `gcc-multilib` if compiling on a `x64` system_
```shell
gcc -g -m32 -z execstack -fno-stack-protector -o shellcode linux-shellcode-func_ptr.cpp
```

### DISABLE ALL PROTECTIONS  
This is the most useful to have static code that is much easier to debug
```shell
gcc -m32 -w -o vuln_disable_canary -o vuln_disable_dep -o vuln_disable_pie -no-pie -z execstack -fno-stack-protector -Wl,-z,-norelro -Wa,--execstack -o shellcode linux-shellcode-func_ptr.cpp
```

### Compile (`x64`)  
```shell
gcc -g -m64 -z execstack -fno-stack-protector -o <Outfile> <shellcode template>
```
