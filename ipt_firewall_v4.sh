#!/bin/bash

IP4ADDR="my static ip"
DNS1="217.31.204.130"
DNS2="193.29.206.206"
SSH_PORT="sshd port number"    # server sshd will be listening on this port number
IP4IFACE="net interface"

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
-A ICMP_input -d ${IP4ADDR} -i ${IP4IFACE} -p icmp -m icmp --icmp-type 4 -j ACCEPT
-A ICMP_input -d ${IP4ADDR} -i ${IP4IFACE} -p icmp -m icmp --icmp-type 12 -j ACCEPT
-A ICMP_input -d ${IP4ADDR} -i ${IP4IFACE} -p icmp -m icmp --icmp-type 3 -j ACCEPT
-A ICMP_input -d ${IP4ADDR} -i ${IP4IFACE} -p icmp -m icmp --icmp-type 11 -j ACCEPT
-A ICMP_input -d ${IP4ADDR} -i ${IP4IFACE} -p icmp -m icmp --icmp-type 0 -m limit --limit 10/sec -j ACCEPT
-A ICMP_input -d ${IP4ADDR} -i ${IP4IFACE} -p icmp -m icmp --icmp-type 8 -m limit --limit 10/sec -j ACCEPT
-A ICMP_input -i ${IP4IFACE} -p icmp -j LnD

:ICMP_output - [0:0]
-A ICMP_output -s ${IP4ADDR} -o ${IP4IFACE} -p icmp -m icmp --icmp-type 4 -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o ${IP4IFACE} -p icmp -m icmp --icmp-type 12 -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o ${IP4IFACE} -p icmp -m icmp --icmp-type 3 -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o ${IP4IFACE} -p icmp -m icmp --icmp-type 3/4 -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o ${IP4IFACE} -p icmp -m icmp --icmp-type 11 -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o ${IP4IFACE} -p icmp -m icmp --icmp-type 8 -m limit --limit 10/sec -j ACCEPT
-A ICMP_output -s ${IP4ADDR} -o ${IP4IFACE} -p icmp -m icmp --icmp-type 0 -m limit --limit 10/sec -j ACCEPT
-A ICMP_output -o ${IP4IFACE} -p icmp -j LnR

# END of chain definitions

# traffic on lo accept
-A INPUT  -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# BANNED IPs should be here
#-A INPUT  -s 23.23.221.92/32 -i ${IP4IFACE} -j LBanned
# or
#-A INPUT  -s 31.184.194.115/32  -i ${IP4IFACE} -j DROP

# IANA Reserved
-A INPUT  -s 10.0.0.0/8      -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 10.0.0.0/8      -o ${IP4IFACE} -j LIANA_Reserved
-A INPUT  -s 127.0.0.0/8     -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 127.0.0.0/8     -o ${IP4IFACE} -j LIANA_Reserved
-A INPUT  -s 169.254.0.0/16  -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 169.254.0.0/16  -o ${IP4IFACE} -j LIANA_Reserved
-A INPUT  -s 172.16.0.0/12   -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 172.16.0.0/12   -o ${IP4IFACE} -j LIANA_Reserved
-A INPUT  -s 192.0.2.0/24    -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 192.0.2.0/24    -o ${IP4IFACE} -j LIANA_Reserved
-A INPUT  -s 192.88.99.0/24  -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 192.88.99.0/24  -o ${IP4IFACE} -j LIANA_Reserved
-A INPUT  -s 192.168.0.0/16  -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 192.168.0.0/16  -o ${IP4IFACE} -j LIANA_Reserved
-A INPUT  -s 198.18.0.0/15   -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 198.18.0.0/15   -o ${IP4IFACE} -j LIANA_Reserved
-A INPUT  -s 198.51.100.0/24 -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 198.51.100.0/24 -o ${IP4IFACE} -j LIANA_Reserved
-A INPUT  -s 203.0.113.0/24  -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 203.0.113.0/24  -o ${IP4IFACE} -j LIANA_Reserved
-A INPUT  -s 240.0.0.0/4     -i ${IP4IFACE} -j LIANA_Reserved
-A OUTPUT -d 240.0.0.0/4     -o ${IP4IFACE} -j LIANA_Reserved

-A INPUT -p tcp -j Portscan

-A INPUT  -i ${IP4IFACE} -p icmp -j ICMP_input
-A OUTPUT -o ${IP4IFACE} -p icmp -j ICMP_output

# DNS 1
-A INPUT  -s ${DNS1} -d ${IP4ADDR} -i ${IP4IFACE} -p udp -m udp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP4ADDR} -d ${DNS1} -o ${IP4IFACE} -p udp -m udp --sport 1024:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT  -s ${DNS1} -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP4ADDR} -d ${DNS1} -o ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

# DNS 2
-A INPUT  -s ${DNS2} -d ${IP4ADDR} -i ${IP4IFACE} -p udp -m udp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP4ADDR} -d ${DNS2} -o ${IP4IFACE} -p udp -m udp --sport 1024:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT  -s ${DNS2} -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP4ADDR} -d ${DNS2} -o ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

# HTTP server
#-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 80 -j ACCEPT
#-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p tcp -m tcp --sport 80 --dport 1024:65535 -j ACCEPT
# HTTPS server
#-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 443 -j ACCEPT
#-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p tcp -m tcp --sport 443 --dport 1024:65535 -j ACCEPT

# HTTP client
-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 80 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
# HTTPS client
-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 443 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

# ssh
-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport ${SSH_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p tcp -m tcp --sport ${SSH_PORT} --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

# ssh client
#-A INPUT  -i ${IP4IFACE} -p tcp --sport 22 -d ${IP4ADDR} --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
#-A OUTPUT -o ${IP4IFACE} -p tcp -s ${IP4ADDR} --sport 1024:65535 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

# SMTP
#-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 25 --dport 1024:65535 -j ACCEPT
#-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 25 -j ACCEPT
#-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 25 -j ACCEPT
#-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p tcp -m tcp --sport 25 --dport 1024:65535 -j ACCEPT

# MSA
#-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 587 -j ACCEPT
#-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p tcp -m tcp --sport 587 --dport 1024:65535 -j ACCEPT

# IMAP
#-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 143 -m state --state NEW,ESTABLISHED -j ACCEPT
#-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p tcp -m tcp --sport 143 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

# NTP client
#-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p udp -m udp --sport 123 --dport 123 -m state --state ESTABLISHED -j ACCEPT
#-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p udp -m udp --sport 123 --dport 123 -m state --state NEW,ESTABLISHED -j ACCEPT

# OpenVPN client
#-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p udp --sport 1194 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
#-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p udp --sport 1054:65534 --dport 1194 -m state --state NEW,ESTABLISHED -j ACCEPT
#-A INPUT  -i tun+ -j ACCEPT
#-A OUTPUT -o tun+ -j ACCEPT
#-A FORWARD -i tun+ -j ACCEPT

# POP3
#-A INPUT  -d ${IP4ADDR} -i ${IP4IFACE} -p tcp -m tcp --sport 1024:65535 --dport 110 -m state --state NEW,ESTABLISHED -j ACCEPT
#-A OUTPUT -s ${IP4ADDR} -o ${IP4IFACE} -p tcp -m tcp --sport 110 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

-A INPUT  -i ${IP4IFACE} -p tcp -j LnD
-A INPUT  -i ${IP4IFACE} -p udp -j LnD
-A OUTPUT -o ${IP4IFACE} -p tcp -j LnR
-A OUTPUT -o ${IP4IFACE} -p udp -j LnR

COMMIT

EOF

exit 0
