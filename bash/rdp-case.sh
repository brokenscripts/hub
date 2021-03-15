#!/bin/bash

# pass: password

# -l    login_name
# -L    local_socket:host:hostport
# -N    Do not execute a remote command.  Just forward a port.

# Open a connection to 192.168.1.14 and then
# forward any connection on local port 3389 to host 192.168.1.54:3389

case "$1" in 

vista-dbg) 
	# Vista (Debugging)
	(sleep 10 && echo 'yes' | 
		xfreerdp +clipboard /u:user /p:password /v:127.0.0.1 /cert:ignore /size:1024x768 || 
		rdesktop -E -u user -p password 127.0.0.1
	) & 
	ssh -luser -N -L 3389:192.168.102.54:3389 192.168.102.14
	;;
vista)
	# Vista
	(sleep 10 ; echo 'yes' | 
		xfreerdp +clipboard /u:user /p:password /v:127.0.0.1 /cert:ignore /size:1024x768 ||
		rdesktop -E -u user -p password 127.0.0.1
	) &
	ssh -luser -N -L 3389:10.200.2.14:3389 192.168.102.14
	;;
2k3)
	# Win2k3
	xfreerdp +clipboard /u:user /p:password /v:127.0.0.1 /cert:ignore /size:1024x768 ||
	rdesktop -u administrator -p password 192.168.102.184
	;;
*) echo "vista-dbg, vista, or 2k3"
	;;
esac
