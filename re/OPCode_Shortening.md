# OPCode Shortening  
```nasm
Offset          Hex             Instruction
--------        --------        --------
00000000        41 5f           pop r15
00000002        c3              ret
```

Shifting this by 1 byte (starting at offset 0x00000001 instead of 0x00000000) changes the pop instruction:  

```nasm
Offset          Hex             Instruction
--------        --------        --------
00000000        5f              pop rdi
00000001        c3              ret
```

`41 5f c3        ->      5f c3`
`pop r15; ret    ->      pop rdi; ret`

```cpp
r15 -> rdi
r14 -> rsi
r13 -> rbp
r12 -> rsp
r11 -> rbx
r10 -> rdx
r9 -> rcx
r8 -> rax
```