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