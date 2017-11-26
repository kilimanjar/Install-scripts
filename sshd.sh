

cat /etc/ssh/sshd_config << EOF
Port {{ ssh_port_number }}
AddressFamily inet
ListenAddress {{ ansible_host }}
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
AllowUsers tonda
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
{% if ansible_distribution == 'CentOS' %}
Subsystem sftp /usr/libexec/openssh/sftp-server
{% endif %}
{% if ansible_distribution == 'Debian' %}
Subsystem sftp /usr/lib/openssh/sftp-server
{% endif %}
SyslogFacility AUTH
TCPKeepAlive no
UseDNS no
UseLogin no
UsePAM no
UsePrivilegeSeparation yes
X11Forwarding no
X11DisplayOffset 10
EOF
