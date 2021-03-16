#!/usr/bin/python3

# Reference: https://github.com/ihack4falafel/ROR13HashGenerator
# Contains plenty of pre-computed hashes

import sys

def ror( dword, bits ):
  return (( dword >> bits | dword << ( 32 - bits ) ) & 0xFFFFFFFF)

def hash(function, bits=13, print_hash=True ):
  function_hash = 0
  for c in str( function ):
    function_hash  = ror( function_hash, bits )
    function_hash  = (function_hash + ord(c))

  if print_hash:
    function_hash = function_hash & 0xFFFFFFFF
    print("[+] 0x%02X = %s" % ( function_hash, function ))
  return function_hash

def main( argv=None ):
  if not argv:
    argv = sys.argv
  try:
    if len( argv ) != 2:
      print(f"Usage: {sys.argv[0]} <function name>")
      print("-------------------------------------")
      print(f"Example: {sys.argv[0]} LoadLibraryA")
      print("[+] 0xEC0E4E8E = LoadLibraryA")
      print("")
    else:
      hash( argv[1] )
  except Exception as e:
    print("[-] ", e)
	
if __name__ == "__main__":
  main()