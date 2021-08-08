; HelloWorld-Stack.nasm
; SLAE32
; Stack
;
; python3 -c 'code=b"Hello World\n"; print(code[::-1].hex())'
; 0a646c726f57206f6c6c6548

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