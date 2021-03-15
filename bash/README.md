# Bash / Shellscripts  
Collection of randomness.  

---

## Misc notes  
Enable i386 architecture on Debian based system(s):  
```bash
sudo dpkg --add-architecture i386  
```

VMWare mount shared folders from host into guest /mnt:  
```bash
sudo /usr/bin/vmhgfs-fuse .host:/ /mnt -o subtype=vmhgfs-fuse,allow_other  
```
