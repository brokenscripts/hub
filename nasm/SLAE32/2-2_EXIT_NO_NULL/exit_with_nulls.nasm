; Filename: exit_with_nulls.nasm
; From SLAE32
;
; 
; objdump -d -M intel exit_with_nulls.nasm
; 
;   exit_with_nulls:     file format elf32-i386   
;   
;   Disassembly of section .text:

;   08049000 <_start>:
;    8049000:       b8 01 00 00 00          mov    eax,0x1
;    8049005:       bb 0a 00 00 00          mov    ebx,0xa
;    804900a:       cd 80                   int    0x80

global _start:

section .text
_start:
    mov eax, 1
    mov ebx, 10
    int 0x80