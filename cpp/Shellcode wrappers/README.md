# Shellcode Template Wrapper

This project describes the how to build an executable from raw shellcode that has been saved to a file and the C++ wrapper program.

## Dependencies

* Raw shellcode saved to file that is to be converted to an executable
  * Shellcode wrapper templates
    * Linux_C_shellcode-template.cpp
    * MS_C_shellcode-template.cpp
  * Compiler for x86 and x86_64
    * Windows: Visual Studios (2015, 2019, etc.)
    * Linux : gcc, llvm, clang, etc.

## Steps to convert shellcode to an executable

1. Convert the shellcode to C++ character array code that can be imported into a template.  To reduce the number of edits required to the Sellcode wrapper template, you can rename the raw shellcode file to  **shellcode.h**

```bash
xxd -i [File Name] > shellcode.h
```

2. Edit the **shellcode.h** to rename `unsigned char[]` variable to **shellcode**, example:  
```cpp
unsigned char shellcode[] = {0xCC, 0x90, 0x90};
```

3. Edit the **shellcode.h** to rename `unsigned int len` variable to **shellcode_len**, example:  
```cpp
unsigned int shellcode_len = 3;
```
**Note**:  If this is an unwanted feature, use sizeof (instead of strlen), since NULLs are not counted.  

4. Edit the appropriate shellcode wrapper template by replacing Line 3 to include the newly created **shellcode.h** file, example:
```cpp
#include "shellcode.h"
```

5. Validate variables `shellcode` and `shellcode_len` are appropriately named in both the **shellcode.h** & **shellcode_wrapper_template.cpp**

3. Compile shellcode wrapper (static addressing)

* Windows
  NOTE: In case of evaluation license issues, please look at the following project. [<https://github.com/beatcracker/VSCELicense>]
  1. Start Visual Studio.
  2. Create a new C++ empty project.  *Note: The compiled executable will match the project name.  
  3. In the Solution Explorer pane, Add Existing Item(s) to include both: `shellcode.h` and `shellcode_wrapper_template.c`  
  4. Set compiler to build option **x86** or **x86_64** with Option **Release**.  The option must match the architecture of the shellcode.  
  5. Set Project Properties -> Code Generation -> `Security Check` : **Disable Security Check (/GS-)**
  6. Set Project Properties -> Code Generation -> `Control Flow Guard` : **No**
  7. Set Project Properties -> Linker -> Advanced -> `Randomized Base Address` : **No**
  8. Set Project Properties -> Linker -> Advanced -> `Data Execution Prevention (DEP)` : **No**
  9. Compile the shellcode wrapper.

* Linux
  * Compile the modified shell code wrapper.
    * Example:

      ```bash
      # Compiling x86
      # Note: Compiling on x86 requires installation of the package: gcc-multilib
      # Disable canary: -o vuln_disable_canary
      # Disable DEP: -o vuln_disable_dep
      # Disable PIE: -o vuln_disable_pie -no-pie
      # Executable stack: -z execstack
      # Prevent stack protector: -fno-stack-protector
      # Disable RELRO: -Wl,-z,norelro
      gcc -g -m32 -z execstack -fno-stack-protector -o <Outfile> <shellcode template>
      # gcc -m32 -w -o vuln_disable_canary -o vuln_disable_dep -o vuln_disable_pie -no-pie -z execstack -fno-stack-protector -Wl,-z,-norelro -Wa,--execstack -o shell shell.cpp
      # Compiling x64
      gcc -g -m64 -z execstack -fno-stack-protector -o <Outfile> <shellcode template>
      ```

5. Run the executable
