#!/usr/bin/python3
"""
Source USB HID Mappings: https://gist.github.com/MightyPork/6da26e382a7ad91b5496ee55fdc73db2
Inspiration: https://dbaser.github.io/2017/04/27/picoctf-2017-for80-just_keyp_trying/
Inspiration: https://bitvijays.github.io/LFC-Forensics.html
"""

"""
Example prep:

tshark -r usb-keyboard-data.pcap -T fields -e usb.capdata
"""

"""
Input information:
0-2  - Byte 0 - Keyboard modifier bits (SHIFT, ALT, CTRL etc)
4-6  - Byte 1 - Reserved
8-10 - Byte 2 - Typical keyboard press
    HOWEVER: Byte 2-7: Up to six keyboard usage indexes
       representing the keys that are currently 'pressed'.
       Order is not important.
       A key is either pressed (present in the buffer) or not pressed.
"""

shift_keys = [0x02, 0x20]
caps_key = 0x39
delete_key = 0x4c
backspace_key = 0x2a

direction_mappings = {
    0x4f: "RIGHT",
    0x50: "LEFT",
    0x51: "UP",
    0x52: "DOWN"
}

usb_codes = {
   0x04: "aA", 0x05: "bB", 0x06: "cC", 0x07: "dD", 0x08: "eE", 0x09: "fF",
   0x0A: "gG", 0x0B: "hH", 0x0C: "iI", 0x0D: "jJ", 0x0E: "kK", 0x0F: "lL",
   0x10: "mM", 0x11: "nN", 0x12: "oO", 0x13: "pP", 0x14: "qQ", 0x15: "rR",
   0x16: "sS", 0x17: "tT", 0x18: "uU", 0x19: "vV", 0x1A: "wW", 0x1B: "xX",
   0x1C: "yY", 0x1D: "zZ", 0x1E: "1!", 0x1F: "2@", 0x20: "3#", 0x21: "4$",
   0x22: "5%", 0x23: "6^", 0x24: "7&", 0x25: "8*", 0x26: "9(", 0x27: "0)",
   0x2C: "  ", 0x2D: "-_", 0x2E: "=+", 0x2F: "[{", 0x30: "]}", 0x31: "\\|",
   0x32: "#~", 0x33: ";:", 0x34: "'\"", 0x35: "`~", 0x36: ",<",  0x37: ".>",
   0x38: "/?", 0x4f: ">", 0x50: "<", 0x4c: "DEL ", 0x2a: "BACKSPACE "
   }

# Variable Declaration
lines = ["", "", "", "", ""]
pos = 0


with open("data.txt", "r") as f:
    for x in f.readlines():
        byte0 = int(x[0:2], 16)
        byte2 = int(x[6:8], 16)

        if byte2 == 0:
            continue

        # Newline or Down Arrow - Move Down in pos list (New sentence)
        if byte2 == 0x51 or byte2 == 0x28:
            pos += 1
            continue

        # Up Arrow - Move Up in pos list (Old sentence)
        if byte2 == 0x52:
            pos -= 1
            continue

        # Print out Delete / Backspace instead of changing the string
        if byte2 == delete_key or byte2 == backspace_key:
            lines[pos] += usb_codes[byte2]
            continue

        # Select the Character based on the Shift key
        if byte0 in shift_keys:
            lines[pos] += usb_codes[byte2][1]
        else:
            lines[pos] += usb_codes[byte2][0]


for x in lines:
    if x != "":
        print(x)
