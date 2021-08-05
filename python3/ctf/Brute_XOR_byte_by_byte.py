c = '\x13\x13eg#v\t\x05\x0f#HE\x04CC\x07\x0f0V\x14\x15\\\x17\t\x0f2AU\x02\x01\x00\x01#\x1fE{\x14\\\x13\x17#qG{\x04\x00\x1e\x11$q\x14J\n'

#goal is string in equal length to c that starts with CSACTF{
goal = "CSACTF{ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijlmnopqrst}"
flag = ''
bit = 0

key = ''
for byt in c:
        if byt != goal[bit]:
                for x in range(0,255):
                        if chr(ord(byt) ^ x) == goal[bit]:
                                key += chr(x)
        bit += 1

print(key)
#Only first seven are known since only know CSACTF{ is given
#trial and error we find
#key = "P@$$w0rd"
key = "P@$$w0rd"
bit=0
for byt in c:
        flag += chr(ord(byt)^ord(key[bit % 8]))
        bit += 1

print(flag)
