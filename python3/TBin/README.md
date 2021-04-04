# TBin.py  
Using PEpper & LIEF's PEReader as a base.  The goal being to grab useful data when ran normally or everything if desired.  

Current args allowed in v0.4 (based on -h):
```
usage: TBin.py [-h] [-a] [-y YARA_RULES_PATH] pe_file

positional arguments:
  pe_file

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             Show all informations
  -y YARA_RULES_PATH, --yara-rules YARA_RULES_PATH
                        Specify a yara-rules directory
```

## Requirements  
```
Python 3.7.3+  
lief == 0.11.4  
```

## Optional  
```
python-magic == 0.4.22  (Adds in pretty 'magic' detection, not required)  
yara_python == 4.0.5  (Adds in the ability to use yara-rules to scan a file)  
  - If using yara_python, download rules from: https://github.com/Yara-Rules/rules  
  - Rules go in ./rules (relative to where the script is ran from) - Or a new path can be specified with -y  
  - Requires (currently) an index.yar that lists every yara rule to load  
```

## To Do
-  [X] Yara
-  [ ] Packer check (optional)  
-  [ ] ClamAV integration (optional)  
