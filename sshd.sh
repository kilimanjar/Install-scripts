#!/bin/bash

. _variables
SFTP_SUBSYSTEM_DESTINATION=""
DEST_FILE="/etc/ssh/sshd_config"


semanage port -a -t ssh_port -p tcp ${SSH_PORT_NUMBER}

if [ -f ${DEST_FILE} ]; then
    cp -a ${DEST_FILE} ${DEST_FILE}.backup-$(date +%F)
fi

# in Debian
if [ -f /usr/lib/openssh/sftp-server ]; then
   SFTP_SUBSYSTEM_DESTINATIN="/usr/lib/openssh/sftp-server"
fi
# in CentOS
if [ -f /usr/libexec/openssh/sftp-server ]; then
   SFTP_SUBSYSTEM_DESTINATIN="/usr/libexec/openssh/sftp-server"
fi

cat > /etc/ssh/sshd_config <<EOF
Port ${SSH_PORT_NUMBER}
AddressFamily inet
ListenAddress ${IP4ADDR}
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
AllowUsers ${SSH_ALLOW_USERS}
AllowTcpForwarding yes
Banner none
ChallengeResponseAuthentication no
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
ClientAliveInterval 15
ClientAliveCountMax 3
Compression yes
GatewayPorts no
#DebianBanner no
HostbasedAuthentication no
IgnoreRhosts yes
KeyRegenerationInterval 3600
LoginGraceTime 50
LogLevel VERBOSE
MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1-96,hmac-sha1
MaxAuthTries 6
MaxStartups 10
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
PermitUserEnvironment no
PrintLastLog yes
PrintMotd no
PubkeyAuthentication yes
RhostsRSAAuthentication no
RSAAuthentication no
ServerKeyBits 1024
StrictModes yes
Subsystem sftp ${SFTP_SUBSYSTEM_DESTINATION}
SyslogFacility AUTH
TCPKeepAlive no
UseDNS no
UseLogin no
UsePAM no
UsePrivilegeSeparation yes
X11Forwarding no
X11DisplayOffset 10
EOF

systemctl restart sshd

exit 0
