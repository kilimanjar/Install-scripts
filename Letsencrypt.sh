#!/bin/bash

MYDOMAIN=my.domain.tld
ANOTHERDOMAIN=my.anotherdomain.tld

useradd -m -s /bin/false letsencrypt
passwd -l letsencrypt

mkdir /etc/letsencrypt

chown letsencrypt:letsencrypt /etc/letsencrypt

su - letsencrypt

curl https://get.acme.sh | sh

mkdir ~/.acme.sh/${MYDOMAIN}

openssl gersa -out ~/.acme.sh/${MYDOMAIN}/${MYDOMAIN}.key 2048

openssl req -new -key ~/.acme.sh/${MYDOMAIN}/${MYDOMAIN}.key -out ~/.acme.sh/${MYDOMAIN}/${MYDOMAIN}.csr -config <(  cat <<-EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn
 
[ dn ]
C = US
ST = New York
L = Rochester
O = End Point
OU = Testing Domain
emailAddress=your-administrative-address@your-awesome-existing-domain.com
CN = ${MYDOMAIN}
 
[ req_ext ]
subjectAltName = @alt_names
 
[ alt_names ]
DNS.1 = ${ANOTHERDOMAIN}
#DNS.2 = possible.anotherdomain.tld
EOF
)

acme.sh --signcsr --csr ~/.acme.sh/${MYDOMAIN}/${MYDOMAIN}.csr \
  -d ${MYDOMAIN}      -w /var/www/${MYDOMAIN} \
  -d ${ANOTHERDOMAIN} -w /var/www/${ANOTHERDOMAIN}

# viduso
#letsencrypt     ALL = NOPASSWD:/bin/systemctl reload nginx
#letsencrypt     ALL = NOPASSWD:/bin/systemctl reload postfix
#letsencrypt     ALL = NOPASSWD:/bin/systemctl reload dovecot

acme.sh --installcert -d ${MYDOMAIN} \
  --certpath /etc/letsencrypt/${MYDOMAIN}.cert.pem \
  --keypath /etc/letsencrypt/${MYDOMAIN}.key \
  --fullchainpath /etc/letsencrypt/${MYDOMAIN}.chain.pem \
  --reloadcmd "sudo systemctl reload nginx; sudo systemctl reload postfix; sudo systemctl reload dovecot"
