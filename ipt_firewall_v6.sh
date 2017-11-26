#!/bin/bash
. _variables

cat > /etc/sysconfig/ip6tables <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]

:LnD - [0:0]
-A LnD -p tcp -j LOG --log-prefix "[TCP drop] " --log-level 6
-A LnD -p udp -j LOG --log-prefix "[UDP drop] " --log-level 6
-A LnD -p ipv6-icmp -j LOG --log-prefix "[ICMP6 drop] " --log-level 6
-A LnD -j DROP

:LnR - [0:0]
-A LnR -p tcp -j LOG --log-prefix "[TCP reject] " --log-level 6
-A LnR -p udp -j LOG --log-prefix "[UDP reject] " --log-level 6
-A LnR -p ipv6-icmp -j LOG --log-prefix "[ICMP6 reject] " --log-level 6
-A LnR -j REJECT --reject-with icmp6-port-unreachable

:LBanned - [0:0]
-A LBanned -j DROP

# Allow trafic on lo
-A INPUT  -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# BANNED IPs should be here
#-A  INPUT  -s 2607:f018:0800:0001:0141:0212:0121:0112/112 -i ${IP6IFACE} -j LBanned

# Allow Link-Local addresses
-A INPUT  -s fe80::/10 -j ACCEPT
-A OUTPUT -s fe80::/10 -j ACCEPT

# Allow multicast
-A INPUT  -d ff00::/8 -j ACCEPT
-A OUTPUT -d ff00::/8 -j ACCEPT

# Allow ICMP
-A INPUT -p icmpv6 -j ACCEPT
-A OUTPUT -p icmpv6 -j ACCEPT

# DNS 1
-A INPUT  -s ${DNS6_1} -d ${IP6ADDR} -i ${IP6IFACE} -p udp -m udp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP6ADDR} -d ${DNS6_1} -o ${IP6IFACE} -p udp -m udp --sport 1024:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT  -s ${DNS6_1} -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP6ADDR} -d ${DNS6_1} -o ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

# DNS 2
-A INPUT  -s ${DNS6_2} -d ${IP6ADDR} -i ${IP6IFACE} -p udp -m udp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP6ADDR} -d ${DNS6_2} -o ${IP6IFACE} -p udp -m udp --sport 1024:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT  -s ${DNS6_2} -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 53 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP6ADDR} -d ${DNS6_2} -o ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

# HTTP server
#-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 80 -j ACCEPT
#-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p tcp -m tcp --sport 80 --dport 1024:65535 -j ACCEPT
# HTTPS server
#-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 443 -j ACCEPT
#-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p tcp -m tcp --sport 443 --dport 1024:65535 -j ACCEPT

# HTTP client
-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 80 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
# HTTPS client
-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 443 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

# SMTP
#-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 25 --dport 1024:65535 -j ACCEPT
#-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 25 -j ACCEPT
#-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 25 -j ACCEPT
#-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p tcp -m tcp --sport 25 --dport 1024:65535 -j ACCEPT

# MSA
#-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 587 -j ACCEPT
#-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p tcp -m tcp --sport 587 --dport 1024:65535 -j ACCEPT

# SYSLOG server
#-A INPUT  -s ${client} -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 6514 -m state --state NEW,ESTABLISHED -j ACCEPT
#-A OUTPUT -s ${IP6ADDR} -d ${client} -o ${IP6IFACE} -p tcp -m tcp --sport 6514 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

# NTP
#-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p udp -m udp --sport 123 --dport 123 -m state --state ESTABLISHED -j ACCEPT
#-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p udp -m udp --sport 123 --dport 123 -m state --state NEW,ESTABLISHED -j ACCEPT

# WHOIS
#-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 43 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
#-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 43 -m state --state NEW,ESTABLISHED -j ACCEPT

# IMAP
#-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 143 -m state --state NEW,ESTABLISHED -j ACCEPT
#-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p tcp -m tcp --sport 143 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT

# POP3S
#-A INPUT  -d ${IP6ADDR} -i ${IP6IFACE} -p tcp -m tcp --sport 1024:65535 --dport 995 -j ACCEPT
#-A OUTPUT -s ${IP6ADDR} -o ${IP6IFACE} -p tcp -m tcp --sport 995 --dport 1024:65535 -j ACCEPT

-A INPUT  -i ${IP6IFACE} -p tcp -j LnD
-A INPUT  -i ${IP6IFACE} -p udp -j LnD
-A OUTPUT -o ${IP6IFACE} -p tcp -j LnR
-A OUTPUT -o ${IP6IFACE} -p udp -j LnR

COMMIT

EOF
systemctl restart ip6tables

exit 0
