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
    mov al, 0x1
    
    xor ebx, ebx
    
    int 0x80

call_shellcode:
    call shellcode
    message: db "Hello World!", 0xA      ; 0xA == Newline in ASCII