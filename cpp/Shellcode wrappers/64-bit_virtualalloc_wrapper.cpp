#include "Windows.h"
#include <stdio.h>
#include "shellcode.h"

int main()
{

	printf("Shellcode Length: %d\n", shellcode_len);
	//Allocate memory with all permissions
	void *shellcode_mem = VirtualAlloc(0, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(shellcode_mem, shellcode, shellcode_len);
	((void(*)())shellcode_mem)();

    return 0;
}