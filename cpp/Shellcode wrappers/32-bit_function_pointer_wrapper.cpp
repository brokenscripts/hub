#include <stdio.h>
#include <string.h>
#include "shellcode.h"

main()
{
	printf("Shellcode Length: %d\n", shellcode_len);
	void (shellcode_ptr) (void);
	shellcode_ptr = (void *)shellcode;
	shellcode_ptr();
}
