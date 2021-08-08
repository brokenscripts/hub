; Filename: exit_no_nulls.nasm
; From SLAE32
;
; 
; objdump -d -M intel exit_no_nulls.nasm
; 
;    exit_no_nulls:     file format elf32-i386
;
;    Disassembly of section .text:
;
;    08049000 <_start>:
;    8049000:       31 c0                   xor    eax,eax
;    8049002:       b0 01                   mov    al,0x1
;    8049004:       31 db                   xor    ebx,ebx
;    8049006:       b3 0a                   mov    bl,0xa (10)      ; This instruction is optional, can be removed since exit doesn't NEED to return 10
;    8049008:       cd 80                   int    0x80
;
;
; Convert to shellcode reference: https://www.commandlinefu.com/commands/view/6051/get-all-shellcode-on-binary-file-from-objdump
;
; objdump -d ./exit_no_nulls|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
;
; "\x31\xc0\xb0\x01\x31\xdb\xb3\x0a\xcd\x80"


global _start:

section .text
_start:
    xor eax, eax    ; Zero out EAX
    mov al, 1       ; Lower half of EAX register
    xor ebx, ebx    ; Zero out EBX
    mov bl, 10      ; Lower half of EBX register
    int 0x80