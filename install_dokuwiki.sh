#!bin/bash

TEMP='mktemp -d'
DOKU_SRC="https://download.dokuwiki.org/out/dokuwiki-c5525093cf2c4f47e2e5d2439fe13964.tgz"
ABOVEWEBROOT="/var/www/${MYWEBDOMAIN}"
WEBROOT="${ABOVEWEBROOT}/www"

curl -L ${DOKU_SRC} | tar xvf - -C ${TEMP}


rm -r ${TEMP}
exit 0
