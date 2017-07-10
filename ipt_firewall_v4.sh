#!/bin/bash

IP4ADDR="my static ip"


cat > iptables <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]

# START of chain definitions

# Log Banned chain definition
:LBanned - [0:0]
-A LBanned -p tcp  -j LOG --log-prefix "[TCP Banned] "  --log-level 6
-A LBanned -p udp  -j LOG --log-prefix "[UDP Banned] "  --log-level 6
-A LBanned -p icmp -j LOG --log-prefix "[ICMP Banned] " --log-level 6
-A LBanned -f -j LOG --log-prefix "[FRAG Banned] " --log-level 6
-A LBanned -j DROP

# Log limit exceeded chain definition
:LDDoS - [0:0]
-A LDDoS -m limit --limit 1/sec --limit-burst 10 -j RETURN
-A LDDoS -j DROP

# Log IANA Reserved chain definition
:LIANA_Reserved - [0:0]
-A LIANA_Reserved -j DROP
-A LIANA_Reserved -p tcp  -j LOG --log-prefix "[IANA Reserved - TCP] "  --log-level 6
-A LIANA_Reserved -p udp  -j LOG --log-prefix "[IANA Reserved - UDP] "  --log-level 6
-A LIANA_Reserved -p icmp -j LOG --log-prefix "[IANA Reserved - ICMP] " --log-level 6
-A LIANA_Reserved -f -j LOG --log-prefix "[IANA Reserved - FRAG] " --log-level 6
-A LIANA_Reserved -j DROP

# Log & Drop chain definition
:LnD - [0:0]
-A LnD -j DROP
-A LnD -p tcp  -j LOG --log-prefix "[TCP drop] "  --log-level 6
-A LnD -p udp  -j LOG --log-prefix "[UDP drop] "  --log-level 6
-A LnD -p icmp -j LOG --log-prefix "[ICMP drop] " --log-level 6
-A LnD -f -j LOG --log-prefix "[FRAG drop] " --log-level 6
-A LnD -j DROP

# Log & Reject chain definition
:LnR - [0:0]
-A LnR -p tcp  -j LOG --log-prefix "[TCP reject] "  --log-level 6
-A LnR -p udp  -j LOG --log-prefix "[UDP reject] "  --log-level 6
-A LnR -p icmp -j LOG --log-prefix "[ICMP reject] " --log-level 6
-A LnR -f -j LOG --log-prefix "[FRAG reject] " --log-level 6
-A LnR -j REJECT --reject-with icmp-port-unreachable

# Log Portscan chain definition
:LPortscan - [0:0]
-A LPortscan -p tcp  -j LOG --log-prefix "[TCP Scan?] "
-A LPortscan -f -j LOG --log-prefix "[FRAG Scan?] "
-A LPortscan -j DROP

# Portscan check, packet traversing chain. If ok, packet continues
:Portscan - [0:0]
-A Portscan -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j LPortscan
-A Portscan -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j LPortscan
-A Portscan -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j LPortscan
-A Portscan -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j LPortscan
-A Portscan -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j LPortscan
-A Portscan -p tcp -m tcp --tcp-flags FIN,ACK FIN -j LPortscan
-A Portscan -p tcp -m tcp --tcp-flags PSH,ACK PSH -j LPortscan
-A Portscan -p tcp -m tcp --tcp-flags ACK,URG URG -j LPortscan
-A Portscan -p tcp -m tcp --tcp-flags SYN,RST,ACK SYN -j LDDoS
-A Portscan -j RETURN

:ICMP_input - [0:0]
-A ICMP_input -d ${IP4ADDR} -i eth0 -p icmp -m icmp --icmp-type 4 -j ACCEPT
-A ICMP_input -d ${IP4ADDR} -i eth0 -p icmp -m icmp --icmp-type 12 -j ACCEPT
-A ICMP_input -d ${IP4ADDR} -i eth0 -p icmp -m icmp --icmp-type 3 -j ACCEPT
-A ICMP_input -d ${IP4ADDR} -i eth0 -p icmp -m icmp --icmp-type 11 -j ACCEPT
-A ICMP_input -d ${IP4ADDR} -i eth0 -p icmp -m icmp --icmp-type 0 -m limit --limit 10/sec -j ACCEPT
-A ICMP_input -d ${IP4ADDR} -i eth0 -p icmp -m icmp --icmp-type 8 -m limit --limit 10/sec -j ACCEPT
-A ICMP_input -i eth0 -p icmp -j LnD

:ICMP_output - [0:0]
-A ICMP_output -s ${IP4ADDR} -o eth0 -p icmp -m icmp --icmp-type 4 -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o eth0 -p icmp -m icmp --icmp-type 12 -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o eth0 -p icmp -m icmp --icmp-type 3 -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o eth0 -p icmp -m icmp --icmp-type 3/4 -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o eth0 -p icmp -m icmp --icmp-type 11 -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o eth0 -p icmp -m icmp --icmp-type 8 -m limit --limit 10/sec -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o eth0 -p icmp -m icmp --icmp-type 0 -m limit --limit 10/sec -j ACCEPT
-A ICMP_output -o eth0 -p icmp -j LnR

# END of chain definitions

# traffic on lo accept
-A INPUT  -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
