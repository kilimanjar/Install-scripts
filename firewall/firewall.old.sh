#!/bin/bash
set -eu

VERBOSE=1
LOGGER_OPTS="-d -p kern.info -t network"
#LOG_LIMIT="-m limit --limit 1/s"
LOG_LIMIT=""
PING_LIMIT="-m limit --limit 10/s"
IP4TABLES='/sbin/iptables'
IP6TABLES='/sbin/ip6tables'
ANYWHERE4='0.0.0.0/0'
ANYWHERE6="::/0"
EXTERNAL_INTERFACE_1="eth0"
EXTERNAL_IP4_1=''
EXTERNAL_NETWORK=''
BROADCAST_NET=''
EXTERNAL_IP6_1=''
INTERNAL_INTERFACE=''
INTERNAL_NETWORK=''
INTERNAL_IP=''
LOOPBACK_INTERFACE='lo'
ISP_NAMESERVERS="" # primary, secondary
LOOPBACK4_NETWORK='127.0.0.0/8'
LOOPBACK6_NETWORK='::1'
CLASS_A='10.0.0.0/8'
CLASS_B='172.16.0.0/12'
CLASS_C='192.168.0.0/16'
CLASS_D_MULTICAST='224.0.0.0/4'
CLASS_E_RESERVED_NET='240.0.0.0/5'
BROADCAST_SRC='0.0.0.0'
BROADCAST_DEST='255.255.255.255'
PRIVPORTS='0:1023'
UNPRIVPORTS='1024:'
TRACEROUTE_SRC_PORTS='32769:65535'
TRACEROUTE_DEST_PORTS='33434:33523'
SSH_HI_PORTS="513:1023"                 # SSH Simultaneous Connections
RSYSLOG_UDP_PORT=""
RSYSLOG_TCP_PORT="6514"
POSTGRESQL_PORT='52345'
#
# ICMP Services
# Set the following variable = 1 if you wish to allow
# local clients to 'ping' external sites.
OUTBOUND_PING=1
#
# Set the following variable = 1 if you wish to allow
# external sites to ping your firewall (stops at the
# firewall).
INBOUND_PING=1
#
# Set the following variable = 1 if you wish to allow
# local clients to 'traceroute' to external sites.
OUTBOUND_TRACEROUTE=1
#
# Set the following variable = 1 if you wish to allow
# external sites to 'traceroute' to your firewall (stops
# at the firewall).
INBOUND_TRACEROUTE=0
# ------------------------------------------------------------------
DNS_CLIENT=1
HTTP_CLIENT=1
HTTPS_CLIENT=0
TELNET_CLIENT=0
WHOIS_CLIENT=1
RSYSLOG_CLIENT=1
RSYSLOG_SERVER_IP="2a02:2b88:0002:1::63e:8235/128"
# ------------------------------------------------------------------

IMAPS_SERVER=0
MY_IMAPS4_CLIENTS="0.0.0.0/0"

IMAP_SERVER=0
MY_IMAP4_CLIENTS="0.0.0.0/0"

MANAGESIEVE_SERVER=0
MY_MANAGESIEVE4_CLIENTS="0.0.0.0/0"

SSH_SERVER=1
MY_SSH4_CLIENTS="0.0.0.0/0"
MY_SSH6_CLIENTS="::/0"
SSH_PORT="30"

SMTP_SERVER=0
MSA_SERVER=0

RSYSLOG_SERVER=0
MY_RSYSLOG4_CLIENTS="37.157.199.247"
MY_RSYSLOG6_CLIENTS="2a02:2b88:2:1::112d:8235/128"

OPENVPN_SERVER=1
OPENVPN_PORT="1194"
OPENVPN_PROTO="tcp"
OPENVPN_IP='10.253.254.0/24'

#
#
# Function definitions
#
function flush_rules()
{
  # Remove any existing rules from all chains
  ${IP4TABLES} -t filter -F
  ${IP4TABLES} -t nat    -F
  ${IP4TABLES} -t mangle -F
  ${IP4TABLES} -t raw    -F

  ${IP6TABLES} -t filter -F
  if [ ${VERBOSE} -gt 0 ]; then
    echo "Firewall: Existing rules from all chains removed." | tee >(logger ${LOGGER_OPTS})
  fi
}

function remove_user_chains()
{
  # Remove any pre-existing user-defined chains
  ${IP4TABLES} -t filter -X
  ${IP4TABLES} -t nat    -X
  ${IP4TABLES} -t mangle -X
  ${IP4TABLES} -t raw    -X

  ${IP6TABLES} -t filter -X
  if [ ${VERBOSE} -gt 0 ]; then
    echo "Firewall: Existing user-defined chains removed." | tee >(logger ${LOGGER_OPTS})
  fi
}

function zero_counts()
{
  ${IP4TABLES} -Z

  ${IP6TABLES} -Z
  if [ ${VERBOSE} -gt 0 ]; then
    echo "Firewall: Counts zeroed." | tee >(logger ${LOGGER_OPTS})
  fi
}

function set_default_policy()
{
  # Set the default policy to drop
  ${IP4TABLES} -t filter -P INPUT       DROP
  ${IP4TABLES} -t filter -P OUTPUT      DROP
  ${IP4TABLES} -t filter -P FORWARD     DROP
#  ${IP4TABLES} -t mangle -P PREROUTING  DROP
#  ${IP4TABLES} -t mangle -P INPUT       DROP
#  ${IP4TABLES} -t mangle -P OUTPUT      DROP
#  ${IP4TABLES} -t mangle -P FORWARD     DROP
#  ${IP4TABLES} -t mangle -P POSTROUTING DROP

  ${IP6TABLES} -t filter -P INPUT      DROP
  ${IP6TABLES} -t filter -P OUTPUT     DROP
  ${IP6TABLES} -t filter -P FORWARD    DROP
  if [ ${VERBOSE} -gt 0 ]; then
    echo "Firewall: Default policy set to DROP." | tee >(logger ${LOGGER_OPTS})
  fi
}

function set_traffic_on_loopback()
{
  ${IP4TABLES} -A INPUT   -i ${LOOPBACK_INTERFACE} -j ACCEPT
  ${IP4TABLES} -A OUTPUT  -o ${LOOPBACK_INTERFACE} -j ACCEPT
  ${IP6TABLES} -A INPUT   -i ${LOOPBACK_INTERFACE} -j ACCEPT
  ${IP6TABLES} -A OUTPUT  -o ${LOOPBACK_INTERFACE} -j ACCEPT
  if [ ${VERBOSE} -gt 0 ]; then
    echo "Firewall: Traffic on loopback interfaces enabled." | tee >(logger ${LOGGER_OPTS})
  fi
}

# End of functions section
# Script starts here
if [ ${EXTERNAL_INTERFACE_1} == "ppp0" ]; then
        EXTERNAL_IP=`/sbin/ifconfig ppp0 |awk '/inet addr/{split($2,x,":"); print x[2]}'`
fi

echo "1" > /proc/sys/net/ipv4/ip_forward
# Enable TCP SYN Cookie Protection
echo "1" > /proc/sys/net/ipv4/tcp_syncookies
# Enable broadcast echo Protection
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
# Disable Source Routed Packets
for f in /proc/sys/net/ipv4/conf/*/accept_source_route; do
    echo "0" > $f
done
# Disable ICMP Redirect Acceptance
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
    echo "0" > $f
done
# Don't send Redirect Messages
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do
    echo "0" > $f
done
## Disable ICMP Redirect Acceptance
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
    echo "0" > $f
done
## Drop Spoofed Packets coming in on an interface, which if replied to,
# would result in the reply going out a different interface.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo "1" > $f
done
# Log packets with impossible addresses.
for f in /proc/sys/net/ipv4/conf/*/log_martians; do
    echo "1" > $f
done


if [ ! -x ${IP4TABLES} ]; then
    echo "Missing ${IP4TABLES}. Please check configuration." | tee >(logger ${LOGGER_OPTS})
    exit 1
fi

# See how we were called.
case ${1} in
  start)
        echo "Starting Firewalling... "

        flush_rules
        remove_user_chains
        zero_counts
        set_default_policy
        set_traffic_on_loopback

        # Define custom chain for possible DDoS attack or SYN-flood scan
        # This chain limits the number of new incoming connections to limit
        # the effectiveness of DDoS attacks                 
        ${IP4TABLES} -N LDDoS
        ${IP6TABLES} -N LDDoS
        ${IP4TABLES} -A LDDoS -m limit --limit 1/s --limit-burst 10 -j RETURN
        ${IP6TABLES} -A LDDoS -m limit --limit 1/s --limit-burst 10 -j RETURN
        # Comment the next line out if you don't want to fill up your logs with these.
        #${IP4TABLES} -A LDDoS -j LOG --log-prefix "[DOS Attack/SYN Scan?] "
        #${IP6TABLES} -A LDDoS -j LOG --log-prefix "[DOS Attack/SYN Scan?] "
        ${IP4TABLES} -A LDDoS -j DROP
        ${IP6TABLES} -A LDDoS -j DROP

        # Define custom chain for possible port-scans
        # This chain logs, then DROPs "Xmas" and Null packets which might indicate
        # a port-scan attempt
        ${IP4TABLES} -N LPortscan
        ${IP6TABLES} -N LPortscan
        ${IP4TABLES} -A LPortscan -p tcp  ${LOG_LIMIT} -j LOG --log-prefix "[TCP Scan?] "
        ${IP4TABLES} -A LPortscan -p udp  ${LOG_LIMIT} -j LOG --log-prefix "[UDP Scan?] "
        ${IP4TABLES} -A LPortscan -p icmp ${LOG_LIMIT} -j LOG --log-prefix "[ICMP Scan?] "
        ${IP4TABLES} -A LPortscan -f      ${LOG_LIMIT} -j LOG --log-prefix "[FRAG Scan?] "
        ${IP4TABLES} -A LPortscan -j DROP
        ${IP6TABLES} -A LPortscan -p tcp  ${LOG_LIMIT} -j LOG --log-prefix "[TCP Scan?] "
        ${IP6TABLES} -A LPortscan -p udp  ${LOG_LIMIT} -j LOG --log-prefix "[UDP Scan?] "
        ${IP6TABLES} -A LPortscan -p icmpv6 ${LOG_LIMIT} -j LOG --log-prefix "[ICMP6 Scan?] "
        ${IP6TABLES} -A LPortscan -j DROP

        ${IP4TABLES} -N LnR
        ${IP6TABLES} -N LnR
        ${IP4TABLES} -A LnR -p tcp  ${LOG_LIMIT} -j LOG --log-prefix "[TCP reject] " --log-level=info
        ${IP4TABLES} -A LnR -p udp  ${LOG_LIMIT} -j LOG --log-prefix "[UDP reject] " --log-level=info
        ${IP4TABLES} -A LnR -p icmp ${LOG_LIMIT} -j LOG --log-prefix "[ICMP reject] " --log-level=info
        ${IP4TABLES} -A LnR -f      ${LOG_LIMIT} -j LOG --log-prefix "[FRAG reject] " --log-level=info
        ${IP4TABLES} -A LnR -j REJECT
        ${IP6TABLES} -A LnR -p tcp  ${LOG_LIMIT} -j LOG --log-prefix "[TCP reject] " --log-level=info
        ${IP6TABLES} -A LnR -p udp  ${LOG_LIMIT} -j LOG --log-prefix "[UDP reject] " --log-level=info
        ${IP6TABLES} -A LnR -p icmpv6 ${LOG_LIMIT} -j LOG --log-prefix "[ICMP6 reject] " --log-level=info
        ${IP6TABLES} -A LnR -j REJECT

        ${IP4TABLES} -N LnD
        ${IP6TABLES} -N LnD
        ${IP4TABLES} -A LnD -j DROP
        ${IP4TABLES} -A LnD -p tcp  ${LOG_LIMIT} -j LOG --log-prefix "[TCP drop] " --log-level=info
        ${IP4TABLES} -A LnD -p udp  ${LOG_LIMIT} -j LOG --log-prefix "[UDP drop] " --log-level=info
        ${IP4TABLES} -A LnD -p icmp ${LOG_LIMIT} -j LOG --log-prefix "[ICMP drop] " --log-level=info
        ${IP4TABLES} -A LnD -f      ${LOG_LIMIT} -j LOG --log-prefix "[FRAG drop] " --log-level=info
        ${IP4TABLES} -A LnD -j DROP

        ${IP6TABLES} -A LnD -p tcp  ${LOG_LIMIT} -j LOG --log-prefix "[TCP drop] " --log-level=info
        ${IP6TABLES} -A LnD -p udp  ${LOG_LIMIT} -j LOG --log-prefix "[UDP drop] " --log-level=info
        ${IP6TABLES} -A LnD -p icmpv6 ${LOG_LIMIT} -j LOG --log-prefix "[ICMP6 drop] " --log-level=info
        ${IP6TABLES} -A LnD -j DROP

        ${IP4TABLES} -N LBanned
        ${IP6TABLES} -N LBanned
        ${IP4TABLES} -A LBanned -p tcp  ${LOG_LIMIT} -j LOG --log-prefix "[TCP Banned] " --log-level=info
        ${IP4TABLES} -A LBanned -p udp  ${LOG_LIMIT} -j LOG --log-prefix "[UDP Banned] " --log-level=info
        ${IP4TABLES} -A LBanned -p icmp ${LOG_LIMIT} -j LOG --log-prefix "[ICMP Banned] " --log-level=info
        ${IP4TABLES} -A LBanned -f      ${LOG_LIMIT} -j LOG --log-prefix "[FRAG Banned] " --log-level=info
        ${IP4TABLES} -A LBanned -j DROP

#       ${IP6TABLES} -A LBanned -p tcp  ${LOG_LIMIT} -j LOG --log-prefix "[TCP Banned] " --log-level=info
#       ${IP6TABLES} -A LBanned -p udp  ${LOG_LIMIT} -j LOG --log-prefix "[UDP Banned] " --log-level=info
#       ${IP6TABLES} -A LBanned -p icmpv6 ${LOG_LIMIT} -j LOG --log-prefix "[ICMP6 Banned] " --log-level=info
        ${IP6TABLES} -A LBanned -j DROP

        # This chain drops connections from IANA reserved IP blocks        
        ${IP4TABLES} -N LIANA_Reserved
        ${IP6TABLES} -N LIANA_Reserved
        ${IP4TABLES} -A LIANA_Reserved -j DROP
        ${IP4TABLES} -A LIANA_Reserved -p tcp  ${LOG_LIMIT} -j LOG --log-prefix "[IANA Reserved - TCP] " --log-level=info
        ${IP4TABLES} -A LIANA_Reserved -p udp  ${LOG_LIMIT} -j LOG --log-prefix "[IANA Reserved - UDP] " --log-level=info
        ${IP4TABLES} -A LIANA_Reserved -p icmp ${LOG_LIMIT} -j LOG --log-prefix "[IANA Reserved - ICMP] " --log-level=info
        ${IP4TABLES} -A LIANA_Reserved -f      ${LOG_LIMIT} -j LOG --log-prefix "[IANA Reserved - FRAG] " --log-level=info
        ${IP4TABLES} -A LIANA_Reserved -j DROP

        ${IP6TABLES} -A LIANA_Reserved -p tcp  ${LOG_LIMIT} -j LOG --log-prefix "[IANA Reserved - TCP] " --log-level=info
        ${IP6TABLES} -A LIANA_Reserved -p udp  ${LOG_LIMIT} -j LOG --log-prefix "[IANA Reserved - UDP] " --log-level=info
        ${IP6TABLES} -A LIANA_Reserved -p icmpv6 ${LOG_LIMIT} -j LOG --log-prefix "[IANA Reserved - ICMP6] " --log-level=info
        ${IP6TABLES} -A LIANA_Reserved -j DROP

        ${IP4TABLES} -N ICMP_input
        ${IP4TABLES} -N ICMP_output
        ${IP6TABLES} -N ICMP_input
        ${IP6TABLES} -N ICMP_output
        ${IP4TABLES} -A ICMP_input -i ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type source-quench -s ${ANYWHERE4} -d ${EXTERNAL_IP4_1} -j ACCEPT
        ${IP4TABLES} -A ICMP_input -i ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type parameter-problem -s ${ANYWHERE4} -d ${EXTERNAL_IP4_1} -j ACCEPT
        ${IP4TABLES} -A ICMP_input -i ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type destination-unreachable -s ${ANYWHERE4} -d ${EXTERNAL_IP4_1} -j ACCEPT
        ${IP4TABLES} -A ICMP_input -i ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type time-exceeded -s ${ANYWHERE4} -d ${EXTERNAL_IP4_1} -j ACCEPT
        ${IP4TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type source-quench -s ${EXTERNAL_IP4_1} -d ${ANYWHERE4} -j ACCEPT
        ${IP4TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type parameter-problem -s ${EXTERNAL_IP4_1} -d ${ANYWHERE4} -j ACCEPT
        ${IP4TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type destination-unreachable -s ${EXTERNAL_IP4_1} -d ${ANYWHERE4} -j ACCEPT
        ${IP4TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type fragmentation-needed -s ${EXTERNAL_IP4_1} -d ${ANYWHERE4} -j ACCEPT
        ${IP4TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type time-exceeded -s ${EXTERNAL_IP4_1} -d ${ANYWHERE4} -j ACCEPT
        # icmpv6 traffic 
        ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type destination-unreachable -s ${ANYWHERE6} -d ${EXTERNAL_IP6_1} -j ACCEPT
        ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type packet-too-big -s ${ANYWHERE6} -d ${EXTERNAL_IP6_1} -j ACCEPT
        ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type time-exceeded -s ${ANYWHERE6} -d ${EXTERNAL_IP6_1} -j ACCEPT
        ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type parameter-problem -s ${ANYWHERE6} -d ${EXTERNAL_IP6_1} -j ACCEPT
#       ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type router-advertisement -s ${ANYWHERE6} -d ${EXTERNAL_IP6_1} -m hl --hl-eq 255 -j ACCEPT
        ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type router-advertisement -s ${ANYWHERE6} -d ${EXTERNAL_IP6_1} -j ACCEPT
#       ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type neighbor-solicitation -s ${ANYWHERE6} -d ${ANYWHERE6} -m hl --hl-eq 255 -j ACCEPT
        ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type neighbor-solicitation -s ${ANYWHERE6} -d ${ANYWHERE6} -j ACCEPT
#       ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type neighbor-advertisement -s ${ANYWHERE6} -d ${ANYWHERE6} -m hl --hl-eq 255 -j ACCEPT
        ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type neighbor-advertisement -s ${ANYWHERE6} -d ${ANYWHERE6} -j ACCEPT
#       ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type redirect -s ${ANYWHERE6} -d ${EXTERNAL_IP6_1} -m hl --hl-eq 255 -j ACCEPT
        ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type destination-unreachable -s ${EXTERNAL_IP6_1} -d ${ANYWHERE6} -j ACCEPT
        ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type packet-too-big -s ${EXTERNAL_IP6_1} -d ${ANYWHERE6} -j ACCEPT
        ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type time-exceeded -s ${EXTERNAL_IP6_1} -d ${ANYWHERE6} -j ACCEPT
        ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type parameter-problem -s ${EXTERNAL_IP6_1} -d ${ANYWHERE6} -j ACCEPT
#       ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type neighbour-solicitation -s ${ANYWHERE6} -d ${ANYWHERE6} -m hl --hl-eq 255 -j ACCEPT
        ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type neighbour-solicitation -s ${ANYWHERE6} -d ${ANYWHERE6} -j ACCEPT
#       ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type neighbour-advertisement -s ${ANYWHERE6} -d ${ANYWHERE6} -m hl --hl-eq 255 -j ACCEPT
        ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type neighbour-advertisement -s ${ANYWHERE6} -d ${ANYWHERE6} -j ACCEPT
#       ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type router-solicitation -s ${EXTERNAL_IP6_1} -d ${ANYWHERE6} -m hl --hl-eq 255 -j ACCEPT
        ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type router-solicitation -s ${EXTERNAL_IP6_1} -d ${ANYWHERE6} -j ACCEPT
        # (0 | 8) Allow OUTPUT pings to anywhere.
        if [ $OUTBOUND_PING -gt 0 ]; then
          ${IP4TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type echo-reply -s ${ANYWHERE4} -d ${EXTERNAL_IP4_1} ${PING_LIMIT} -j ACCEPT
          ${IP4TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type echo-request -s ${EXTERNAL_IP4_1} -d ${ANYWHERE4} ${PING_LIMIT} -j ACCEPT
          ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type echo-reply -s ${ANYWHERE6} -d ${EXTERNAL_IP6_1} ${PING_LIMIT} -j ACCEPT
          ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type echo-request -s ${EXTERNAL_IP6_1} -d ${ANYWHERE6} ${PING_LIMIT} -j ACCEPT
          if [ ${VERBOSE} -gt 0 ]; then
            echo "Firewall: Outbound ping enabled" | tee >(logger ${LOGGER_OPTS})
          fi
        fi
        # (0 | 8) Allow incoming pings from anywhere
        #       (stops at firewall).
        if [ $INBOUND_PING -gt 0 ]; then
          ${IP4TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type echo-request -s ${ANYWHERE4} -d ${EXTERNAL_IP4_1} ${PING_LIMIT} -j ACCEPT
          ${IP4TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmp --icmp-type echo-reply -s ${EXTERNAL_IP4_1} -d ${ANYWHERE4} ${PING_LIMIT} -j ACCEPT
          ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type echo-request -s ${ANYWHERE6} -d ${EXTERNAL_IP6_1} ${PING_LIMIT} -j ACCEPT
          ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 --icmpv6-type echo-reply -s ${EXTERNAL_IP6_1} -d ${ANYWHERE6} ${PING_LIMIT} -j ACCEPT
          if [ ${VERBOSE} -gt 0 ]; then
            echo "Firewall: Inbound ping enabled" | tee >(logger ${LOGGER_OPTS})
          fi
        fi
        ${IP4TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmp -s ${ANYWHERE4} -j LnD
        ${IP4TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmp -d ${ANYWHERE4} -j LnR
        ${IP6TABLES} -A ICMP_input  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 -s ${ANYWHERE6} -j DROP
        ${IP6TABLES} -A ICMP_output -o ${EXTERNAL_INTERFACE_1} -p icmpv6 -d ${ANYWHERE6} -j LnR

        # This chain is for bad packed testing
        ${IP4TABLES} -N Portscan
        ${IP6TABLES} -N Portscan
        # Disallow packets frequently used by port-scanners
        ${IP4TABLES} -A Portscan -p tcp --tcp-flags ALL ALL         -j LPortscan
        ${IP6TABLES} -A Portscan -p tcp --tcp-flags ALL ALL         -j LPortscan
        ${IP4TABLES} -A Portscan -p tcp --tcp-flags ALL NONE        -j LPortscan
        ${IP6TABLES} -A Portscan -p tcp --tcp-flags ALL NONE        -j LPortscan
        ${IP4TABLES} -A Portscan -p tcp --tcp-flags SYN,FIN SYN,FIN -j LPortscan
        ${IP6TABLES} -A Portscan -p tcp --tcp-flags SYN,FIN SYN,FIN -j LPortscan
        ${IP4TABLES} -A Portscan -p tcp --tcp-flags SYN,RST SYN,RST -j LPortscan
        ${IP6TABLES} -A Portscan -p tcp --tcp-flags SYN,RST SYN,RST -j LPortscan
        ${IP4TABLES} -A Portscan -p tcp --tcp-flags FIN,RST FIN,RST -j LPortscan
        ${IP6TABLES} -A Portscan -p tcp --tcp-flags FIN,RST FIN,RST -j LPortscan
        ${IP4TABLES} -A Portscan -p tcp --tcp-flags ACK,FIN FIN     -j LPortscan
        ${IP6TABLES} -A Portscan -p tcp --tcp-flags ACK,FIN FIN     -j LPortscan
        ${IP4TABLES} -A Portscan -p tcp --tcp-flags ACK,PSH PSH     -j LPortscan
        ${IP6TABLES} -A Portscan -p tcp --tcp-flags ACK,PSH PSH     -j LPortscan
        ${IP4TABLES} -A Portscan -p tcp --tcp-flags ACK,URG URG     -j LPortscan
        ${IP6TABLES} -A Portscan -p tcp --tcp-flags ACK,URG URG     -j LPortscan
        # SYN-Flood (Request for new connection; large number indicate possible DDoS-type attack; same as --syn)
        ${IP4TABLES} -A Portscan -p tcp --tcp-flags SYN,RST,ACK SYN -j LDDoS
        ${IP6TABLES} -A Portscan -p tcp --tcp-flags SYN,RST,ACK SYN -j LDDoS
        ${IP4TABLES} -A Portscan -j RETURN
        ${IP6TABLES} -A Portscan -j RETURN

        # -----------------------------------
        # PACKET STARTS TRAVERSING RULES HERE
        # -----------------------------------
        #
        # ./firewall.banned contains a list of IPs
        # to block all access, both inbound and outbound.
        # The file should contain IP addresses with CIDR
        # netmask, one per line:
        #
        # NOTE: No comments are allowed in the file.
        #
        # 111.0.0.0/8                   - To block a Class-A network
        # 111.222.0.0/16                - To block a Class-B network
        # 111.222.254.0/24              - To block a Class-C network
        # 111.222.254.244/32            - To block a single IP address
        # The CIDR netmask number describes the number of bits
        # in the network portion of the address, and may be on
        # any boundary.
        if [ -f /etc/firewall/firewall.banlist4 ]; then
            while read BANNED; do
                ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1}  -s ${BANNED} -j LBanned
                ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1}  -d ${BANNED} -j LBanned
                ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1}  -s ${BANNED} -j LBanned
                ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1}  -d ${BANNED} -j LBanned
                ${IP4TABLES} -A FORWARD -d ${BANNED} -j LBanned
                ${IP4TABLES} -A FORWARD -s ${BANNED} -j LBanned
            done < /etc/firewall/firewall.banlist4
            echo "Firewall: Banned addresses v4 added to rule set." | tee >(logger ${LOGGER_OPTS})
        else
            echo "Firewall: Banned address/network v4 file not found." | tee >(logger ${LOGGER_OPTS})
        fi
        if [ -f /etc/firewall/firewall.banlist6 ]; then
            while read BANNED; do
                ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1}  -s ${BANNED} -j LBanned
                ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1}  -d ${BANNED} -j LBanned
                ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1}  -s ${BANNED} -j LBanned
                ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1}  -d ${BANNED} -j LBanned
                ${IP6TABLES} -A FORWARD -d ${BANNED} -j LBanned
                ${IP6TABLES} -A FORWARD -s ${BANNED} -j LBanned
            done < /etc/firewall/firewall.banlist6
            echo "Firewall: Banned addresses v6 added to rule set." | tee >(logger ${LOGGER_OPTS})
        else
            echo "Firewall: Banned address/network v6 file not found." | tee >(logger ${LOGGER_OPTS})
        fi

        # Refuse connections from IANA-reserved blocks
        if [ -f /etc/firewall/firewall.iana_reserved4 ]; then
            while read RESERVED; do
              ${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -s ${RESERVED} -j LIANA_Reserved
              #${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -d ${RESERVED} -j LIANA_Reserved
              #${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -s ${RESERVED} -j LIANA_Reserved
              ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -d ${RESERVED} -j LIANA_Reserved
            done < /etc/firewall/firewall.iana_reserved4
            echo "Firewall: Connections from v4 IANA-reserved addresses blocked" | tee >(logger ${LOGGER_OPTS})
        else
            echo "Firewall: v4 IANA-reserved address/network file not found." | tee >(logger ${LOGGER_OPTS})
        fi

        if [ -f /etc/firewall/firewall.iana_reserved6 ]; then
            while read RESERVED; do
              ${IP6TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -s ${RESERVED} -j LIANA_Reserved
              #${IP6TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -d ${RESERVED} -j LIANA_Reserved
              #${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -s ${RESERVED} -j LIANA_Reserved
              ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -d ${RESERVED} -j LIANA_Reserved
            done < /etc/firewall/firewall.iana_reserved6
            echo "Firewall: Connections from v6 IANA-reserved addresses blocked" | tee >(logger ${LOGGER_OPTS})
        else
            echo "Firewall: v6 IANA-reserved address/network file not found." | tee >(logger ${LOGGER_OPTS})
        fi

        # Refuse directed broadcasts; you may choose not to log these,as they can fill up your logs quickly
        #${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -d ${EXTERNAL_NETWORK} ${LOG_LIMIT} -j LOG --log-prefix "[Directed Broadcast] "
#       ${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -d ${EXTERNAL_NETWORK} -j DROP
        #${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -d $BROADCAST_NET ${LOG_LIMIT} -j LOG --log-prefix "[Directed Broadcast] "
        ${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -d ${BROADCAST_NET} -j DROP
        # Refuse limited broadcasts
        #${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -d 255.255.255.255 ${LOG_LIMIT} -j LOG --log-prefix "[Limited Broadcast] "
        ${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -d ${BROADCAST_DEST} -j DROP
        # Disallow fragmented packets.  This may not be as necessary as it once was.
        # Comment it out with # if desired.
        #${IP4TABLES} -A INPUT -f -i ${EXTERNAL_INTERFACE_1} -j LnD
        #${IP4TABLES} -A INPUT -f -i $INTERNAL_INTERFACE -j LnD
        # Spoofing and Bad Addresses
        # Refuse spoofed packets.
        # Ignore blatantly illegal source addresses.
        # Protect yourself from sending to bad addresses.
        # Refuse spoofed packets pretending to be from
        # the external interface's IP address.
        ${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -s ${EXTERNAL_IP4_1} -j LnD
        # Refuse malformed broadcast packets.
        ${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -s ${BROADCAST_DEST} -j LnD
        ${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -d ${BROADCAST_SRC}  -j LnD
        ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -s ${BROADCAST_DEST} -j LnD
        ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -d ${BROADCAST_SRC}  -j LnD
        # Refuse Class-D Multicast addresses.
        # Multicast is only illegal as a source address.
        # Multicast uses UDP.
        ${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -s ${CLASS_D_MULTICAST} -j LnD
        ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -s ${CLASS_D_MULTICAST} -j LnR
        # Traffic on external interface
        ${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -s 0.0.0.0/8 -j LnD
        ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -s 0.0.0.0/8 -j LnR

        ${IP4TABLES} -A INPUT -p tcp -j Portscan
        ${IP6TABLES} -A INPUT -p tcp -j Portscan

        ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p icmp -j ICMP_input
        ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p icmp -j ICMP_output
        ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p icmpv6 -j ICMP_input
        ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p icmpv6 -j ICMP_output

        #
        # DNS client modes (53)
        if [ $DNS_CLIENT -gt 0 ]; then
            for ISPNMSRVR in ${ISP_NAMESERVERS}; do
              ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p udp -s ${ISPNMSRVR} --sport 53 -d ${EXTERNAL_IP4_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
              ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp -s ${EXTERNAL_IP4_1} --sport ${UNPRIVPORTS} -d ${ISPNMSRVR} --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
              ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ISPNMSRVR} --sport 53 -d ${EXTERNAL_IP4_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
              ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport ${UNPRIVPORTS} -d ${ISPNMSRVR} --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
              #${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p udp --sport 53 -d ${EXTERNAL_IP4_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
              #${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp -s ${EXTERNAL_IP4_1} --sport ${UNPRIVPORTS} --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
              #${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p udp --sport 53 -d ${EXTERNAL_IP6_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
              #${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp -s ${EXTERNAL_IP6_1} --sport ${UNPRIVPORTS} --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
              if [ ${VERBOSE} -gt 0 ]; then
                  echo "Firewall: DNS client connection to ${ISPNMSRVR} enabled." | tee >(logger ${LOGGER_OPTS})
              fi
            done
        fi
        #
        # TCP Services on selected ports.
        # SMTP server (25)
        if [ $SMTP_SERVER -gt 0 ]; then
            ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE4} --sport 25 -d ${EXTERNAL_IP4_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport ${UNPRIVPORTS} -d ${ANYWHERE4} --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE6} --sport 25 -d ${EXTERNAL_IP6_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP6_1} --sport ${UNPRIVPORTS} -d ${ANYWHERE6} --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
            # Receiving Mail as a Local SMTP server (25)
            ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE4} --sport ${UNPRIVPORTS} -d ${EXTERNAL_IP4_1} --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport 25 -d ${ANYWHERE4} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE6} --sport ${UNPRIVPORTS} -d ${EXTERNAL_IP6_1} --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP6_1} --sport 25 -d ${ANYWHERE6} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            if [ ${VERBOSE} -gt 0 ]; then
                echo "Firewall: SMTP server enabled" | tee >(logger ${LOGGER_OPTS})
            fi
        fi
        #
        # MSA server (587)
        if [ $MSA_SERVER -gt 0 ]; then
            ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE4} --sport ${UNPRIVPORTS} -d ${EXTERNAL_IP4_1} --dport 587 -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport 587 -d ${ANYWHERE4} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            if [ ${VERBOSE} -gt 0 ]; then
                echo "Firewall: MSA server enabled" | tee >(logger ${LOGGER_OPTS})
            fi
        fi
        #
        # IMAPS server (993)
        if [ $IMAPS_SERVER -gt 0 ]; then
           for MY_IMAPS_CLIENT in ${MY_IMAPS4_CLIENTS}; do
            ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${MY_IMAPS_CLIENT} --sport ${UNPRIVPORTS} -d ${EXTERNAL_IP4_1} --dport 993 -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport 993 -d ${MY_IMAPS_CLIENT} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
               if [ ${VERBOSE} -gt 0 ]; then
                  echo "Firewall: Remote site ${MY_IMAPS_CLIENT} may access local IMAPS server" | tee >(logger ${LOGGER_OPTS})
               fi
           done
        fi
        #
        # IMAP server (143)
        if [ $IMAP_SERVER -gt 0 ]; then
           for MY_IMAP_CLIENT in ${MY_IMAP4_CLIENTS}; do
            ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${MY_IMAP_CLIENT} --sport ${UNPRIVPORTS} -d ${EXTERNAL_IP4_1} --dport 143 -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport 143 -d ${MY_IMAP_CLIENT} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
               if [ ${VERBOSE} -gt 0 ]; then
                  echo "Firewall: Remote site ${MY_IMAP_CLIENT} may access local IMAP server" | tee >(logger ${LOGGER_OPTS})
               fi
           done
        fi
        #
        # MANAGESIEVE server (4190)
        if [ ${MANAGESIEVE_SERVER} -gt 0 ]; then
           for MY_MANAGESIEVE_CLIENT in ${MY_MANAGESIEVE4_CLIENTS}; do
            ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${MY_MANAGESIEVE_CLIENT} --sport ${UNPRIVPORTS} -d ${EXTERNAL_IP4_1} --dport 4190 -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport 4190 -d ${MY_MANAGESIEVE_CLIENT} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
               if [ ${VERBOSE} -gt 0 ]; then
                  echo "Firewall: Remote site ${MY_MANAGESIEVE_CLIENT} may access local MANAGESIEVE server." | tee >(logger ${LOGGER_OPTS})
               fi
           done
        fi
        #
        # TELNET client (23)
        if [ $TELNET_CLIENT -gt 0 ]; then
            ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE4} --sport 23 -d ${EXTERNAL_IP4_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport ${UNPRIVPORTS} -d ${ANYWHERE4} --dport 23 -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE6} --sport 23 -d ${EXTERNAL_IP6_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP6_1} --sport ${UNPRIVPORTS} -d ${ANYWHERE6} --dport 23 -m state --state NEW,ESTABLISHED -j ACCEPT
            if [ ${VERBOSE} -gt 0 ]; then
                echo "Firewall: Clients may access remote TELNET servers" | tee >(logger ${LOGGER_OPTS})
            fi
        fi
        #
        # SSH server ()
        if [ ${SSH_SERVER} -gt 0 ]; then
        for MY_SSH_CLIENT in ${MY_SSH4_CLIENTS}; do
          ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${MY_SSH_CLIENT} --sport ${UNPRIVPORTS} -d ${EXTERNAL_IP4_1} --dport ${SSH_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
          ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport ${SSH_PORT} -d ${MY_SSH_CLIENT} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
          #${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -p tcp --sport $SSH_HI_PORTS --dport $SSH_PORT -s $MY_SSH_CLIENT -d ${EXTERNAL_IP4_1} -j ACCEPT
          #${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -m state --state ESTABLISHED,RELATED --sport $SSH_PORT --dport $SSH_HI_PORTS -s ${EXTERNAL_IP4_1} -d $MY_SSH_CLIENT -j ACCEPT
          if [ ${VERBOSE} -gt 0 ]; then
            echo "Firewall: Remote site ${MY_SSH_CLIENT} may access local SSH server" | tee >(logger ${LOGGER_OPTS})
          fi
        done
        #for MY_SSH_CLIENT in ${MY_SSH6_CLIENTS}; do
          #${IP6TABLES} -A SSH_server_input  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${MY_SSH_CLIENT} --sport ${UNPRIVPORTS} -d ${EXTERNAL_IP6_1} --dport ${SSH_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
          #${IP6TABLES} -A SSH_server_output -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP6_1} --sport ${SSH_PORT} -d ${MY_SSH_CLIENT} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
          ##${IP6TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -p tcp --sport ${SSH_HI_PORTS} --dport ${SSH_PORT} -s $MY_SSH_CLIENT -d ${EXTERNAL_IP6_1} -j ACCEPT
          ##${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -m state --state ESTABLISHED,RELATED --sport $SSH_PORT --dport $SSH_HI_PORTS -s ${EXTERNAL_IP6_1} -d $MY_SSH_CLIENT -j ACCEPT
          #if [ ${VERBOSE} -gt 0 ]; then
            #echo "Firewall: Remote site ${MY_SSH_CLIENT} may access local SSH server" | tee >(logger ${LOGGER_OPTS})
          #fi
        #done
        fi
        #
        # RSYSLOG client ()
        if [ ${RSYSLOG_CLIENT} -gt 0 ]; then
            #${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${RSYSLOG_SERVER_IP} --sport ${RSYSLOG_TCP_PORT} -d ${EXTERNAL_IP4_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            #${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport ${UNPRIVPORTS} -d ${RSYSLOG_SERVER_IP} --dport ${RSYSLOG_TCP_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
            #${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p udp -s ${RSYSLOG_SERVER_IP} --sport ${RSYSLOG_UDP_PORT} -d ${EXTERNAL_IP4_1} --dport ${RSYSLOG_UDP_PORT} -m state --state ESTABLISHED -j ACCEPT
            #${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp -s ${EXTERNAL_IP4_1} --sport ${RSYSLOG_UDP_PORT} -d ${RSYSLOG_SERVER_IP} --dport ${RSYSLOG_UDP_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${RSYSLOG_SERVER_IP} --sport ${RSYSLOG_TCP_PORT} -d ${EXTERNAL_IP6_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP6_1} --sport ${UNPRIVPORTS} -d ${RSYSLOG_SERVER_IP} --dport ${RSYSLOG_TCP_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
            #${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p udp -s ${RSYSLOG_SERVER_IP} --sport ${RSYSLOG_UDP_PORT} -d ${EXTERNAL_IP6_1} --dport ${RSYSLOG_UDP_PORT} -m state --state ESTABLISHED -j ACCEPT
            #${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp -s ${EXTERNAL_IP6_1} --sport ${RSYSLOG_UDP_PORT} -d ${RSYSLOG_SERVER_IP} --dport ${RSYSLOG_UDP_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
            if [ ${VERBOSE} -gt 0 ]; then
            echo "Firewall: Client may access remote RSYSLOG server." | tee >(logger ${LOGGER_OPTS})
            fi
        fi
        #
        # RSYSLOG server ()
        if [ ${RSYSLOG_SERVER} -gt 0 ]; then
            for RSYSLOG_CLIENT in ${MY_RSYSLOG4_CLIENTS}; do
#               ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${RSYSLOG_CLIENT} --sport ${UNPRIVPORTS} -d ${EXTERNAL_IP4_1} --dport ${RSYSLOG_TCP_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
#               ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport ${RSYSLOG_TCP_PORT} -d ${RSYSLOG_CLIENT} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
#               ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p udp -s ${RSYSLOG_CLIENT} --sport ${RSYSLOG_UDP_PORT} -d ${EXTERNAL_IP4_1} --dport ${RSYSLOG_UDP_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
#               ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp -s ${EXTERNAL_IP4_1} --sport ${RSYSLOG_UDP_PORT} -d ${RSYSLOG_CLIENT} --dport ${RSYSLOG_UDP_PORT} -m state --state ESTABLISHED -j ACCEPT
                if [ ${VERBOSE} -gt 0 ]; then
                    echo "Firewall: Remote site ${RSYSLOG_CLIENT} may access local RSYSLOG server." | tee >(logger ${LOGGER_OPTS})
                fi
            done
            for RSYSLOG_CLIENT in ${MY_RSYSLOG6_CLIENTS}; do
#               ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${RSYSLOG_CLIENT} --sport ${UNPRIVPORTS} -d ${EXTERNAL_IP6_1} --dport ${RSYSLOG_TCP_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
#               ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP6_1} --sport ${RSYSLOG_TCP_PORT} -d ${RSYSLOG_CLIENT} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
#               ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p udp -s ${RSYSLOG_CLIENT} --sport ${RSYSLOG_UDP_PORT} -d ${EXTERNAL_IP6_1} --dport ${RSYSLOG_UDP_PORT} -m state --state NEW,ESTABLISHED -j ACCEPT
#               ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp -s ${EXTERNAL_IP6_1} --sport ${RSYSLOG_UDP_PORT} -d ${RSYSLOG_CLIENT} --dport ${RSYSLOG_UDP_PORT} -m state --state ESTABLISHED -j ACCEPT
                if [ ${VERBOSE} -gt 0 ]; then
                    echo "Firewall: Remote site ${RSYSLOG_CLIENT} may access local RSYSLOG server." | tee >(logger ${LOGGER_OPTS})
                fi
            done
        fi
        #
        # HTTP client (80)
        if [ $HTTP_CLIENT -gt 0 ]; then
            ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE4} --sport 80 -d ${EXTERNAL_IP4_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport ${UNPRIVPORTS} -d ${ANYWHERE4} --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE6} --sport 80 -d ${EXTERNAL_IP6_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP6_1} --sport ${UNPRIVPORTS} -d ${ANYWHERE6} --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
            if [ ${VERBOSE} -gt 0 ]; then
                echo "Firewall: Clients may access remote HTTP servers" | tee >(logger ${LOGGER_OPTS})
            fi
        fi
        #
        # HTTPS client (443)
        if [ $HTTPS_CLIENT -gt 0 ]; then
            ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE4} --sport 443 -d ${EXTERNAL_IP4_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport ${UNPRIVPORTS} -d ${ANYWHERE4} --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE6} --sport 443 -d ${EXTERNAL_IP6_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP6_1} --sport ${UNPRIVPORTS} -d ${ANYWHERE6} --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
            if [ ${VERBOSE} -gt 0 ]; then
                echo "Firewall: Clients may access remote HTTPS servers" | tee >(logger ${LOGGER_OPTS})
            fi
        fi
        #
        # WHOIS client (43)
        if [ $WHOIS_CLIENT -gt 0 ]; then
            ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE4} --sport 43 -d ${EXTERNAL_IP4_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP4_1} --sport ${UNPRIVPORTS} --dport 43 -d ${ANYWHERE4} -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp -s ${ANYWHERE6} --sport 43 -d ${EXTERNAL_IP6_1} --dport ${UNPRIVPORTS} -m state --state ESTABLISHED -j ACCEPT
            ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp -s ${EXTERNAL_IP6_1} --sport ${UNPRIVPORTS} --dport 43 -d ${ANYWHERE6} -m state --state NEW,ESTABLISHED -j ACCEPT
            if [ ${VERBOSE} -gt 0 ]; then
                echo "Firewall: Clients may access remote WHOIS servers" | tee >(logger ${LOGGER_OPTS})
            fi
        fi
        #
        # UDP - Accept only on selected ports
        # TRACEROUTE
        # Traceroute usually uses -s 32769:65535 -d 33434:33523
        if [ $OUTBOUND_TRACEROUTE -gt 0 ]; then
            # Enable outgoing TRACEROUTE requests
            ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp -s ${EXTERNAL_IP4_1} --sport ${TRACEROUTE_SRC_PORTS} -d ${ANYWHERE4} --dport ${TRACEROUTE_DEST_PORTS} -j ACCEPT
            ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp -s ${EXTERNAL_IP6_1} --sport ${TRACEROUTE_SRC_PORTS} -d ${ANYWHERE6} --dport ${TRACEROUTE_DEST_PORTS} -j ACCEPT
            if [ ${VERBOSE} -gt 0 ]; then
                echo "Firewall: Outbound TRACEROUTE enabled" | tee >(logger ${LOGGER_OPTS})
            fi
        fi
        if [ $INBOUND_TRACEROUTE -gt 0 ]; then
            # Enable incoming TRACEROUTE query
            ${IP4TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -p udp -s ${ANYWHERE4} --sport ${TRACEROUTE_SRC_PORTS} -d ${EXTERNAL_IP4_1} --dport ${TRACEROUTE_DEST_PORTS} -j ACCEPT
            ${IP6TABLES} -A INPUT -i ${EXTERNAL_INTERFACE_1} -p udp -s ${ANYWHERE6} --sport ${TRACEROUTE_SRC_PORTS} -d ${EXTERNAL_IP6_1} --dport ${TRACEROUTE_DEST_PORTS} -j ACCEPT
            if [ ${VERBOSE} -gt 0 ]; then
                echo "Firewall: Inbound TRACEROUTE enabled" | tee >(logger ${LOGGER_OPTS})
            fi
        fi
        # OpenVPN server*
        if [ $OPENVPN_SERVER -gt 0 ]; then
            ${IP4TABLES} -A INPUT   -i ${EXTERNAL_INTERFACE_1} -p ${OPENVPN_PROTO} --dport ${OPENVPN_PORT} -j ACCEPT
            ${IP4TABLES} -A OUTPUT  -o ${EXTERNAL_INTERFACE_1} -p ${OPENVPN_PROTO} --sport ${OPENVPN_PORT} -j ACCEPT
            # Traffic on OpenVPN interface
            ${IP4TABLES} -A INPUT   -i tun0 -j ACCEPT
            ${IP4TABLES} -A OUTPUT  -o tun0 -j ACCEPT
            #${IP4TABLES} -A FORWARD -i tun0 -j ACCEPT
            ${IP4TABLES} -A FORWARD -i tun0 -o ${EXTERNAL_INTERFACE_1} -s ${OPENVPN_IP} -m state --state NEW,ESTABLISHED -j ACCEPT
            ${IP4TABLES} -A FORWARD -o tun0 -i ${EXTERNAL_INTERFACE_1} -d ${OPENVPN_IP} -m state --state ESTABLISHED -j ACCEPT
            #*******************OpenVPN traffic routing ************************************
            ${IP4TABLES} -t nat -A POSTROUTING -o eth0 -s ${OPENVPN_IP} -j SNAT --to-source ${EXTERNAL_IP4_1} # seems faster option
            #${IP4TABLES} -t nat -A POSTROUTING -o eth0 -s ${OPENVPN_IP} -j MASQUERADE
            if [ ${VERBOSE} -gt 0 ]; then
                echo "Firewall: OPENVPN server enabled" | tee >(logger ${LOGGER_OPTS})
            fi
        fi
        # -------------------------------------------------------------
        # DROP (on input), REJECT (output) and LOG anything else on the external (red) interface
        ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp  -s ${ANYWHERE4} -j LnD
        ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp  -d ${ANYWHERE4} -j LnR
        ${IP4TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p udp  -s ${ANYWHERE4} -j LnD
        ${IP4TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp  -d ${ANYWHERE4} -j LnR
        ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p tcp  -s ${ANYWHERE6} -j LnD
        ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p tcp  -d ${ANYWHERE6} -j LnR
        ${IP6TABLES} -A INPUT  -i ${EXTERNAL_INTERFACE_1} -p udp  -s ${ANYWHERE6} -j LnD
        ${IP6TABLES} -A OUTPUT -o ${EXTERNAL_INTERFACE_1} -p udp  -d ${ANYWHERE6} -j LnR

        # set it here, to be modules loaded
        sysctl -q net.ipv4.netfilter.ip_conntrack_tcp_timeout_established=3600

        ;;
  stop)
        echo -n "Shutting Firewalling: "
        flush_rules
        remove_user_chains
        zero_counts
        set_default_policy
        set_traffic_on_loopback
        ;;
  status)
        status ${IP4TABLES}
        ;;
  restart|reload)
        $0 stop
        $0 start
        ;;
  *)
        echo "Usage: iptables {start|stop|status|restart|reload}"
        exit 1
esac
echo "done"

exit 0
