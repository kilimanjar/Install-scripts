#!bin/bash

#TEMP='mktemp -d'
DOKU_SRC="https://download.dokuwiki.org/out/dokuwiki-c5525093cf2c4f47e2e5d2439fe13964.tgz"

. _variables

curl -L ${DOKU_SRC} | tar zxf - --strip-components=1 -C ${WEBROOT}
touch ${WEBROOT}/conf/local.php.bak
touch ${WEBROOT}/conf/plugins.local.php.bak
chown -R ${WWW_DATA_USER_NAME}:${WWW_DATA_GROUP_NAME} ${WEBROOT}
semanage fcontext -a -t httpd_sys_rw_content_t "${WEBROOT}/data(/.*)?"
restorecon -R -v ${WEBROOT}/data
semanage fcontext -a -t httpd_sys_rw_content_t "${WEBROOT}/lib/plugins(/.*)?"
restorecon -R -v ${WEBROOT}/lib/plugins
semanage fcontext -a -t httpd_sys_rw_content_t "${WEBROOT}/lib/tpl(/.*)?"
restorecon -R -v ${WEBROOT}/lib/tpl
semanage fcontext -a -t httpd_sys_rw_content_t "${WEBROOT}/conf(/.*)?"
restorecon -R -v ${WEBROOT}/conf

echo "Now run install.php from browser to do basic dokuwiki configuration."
read -n1 -r -p "Press any key to continue..."

mkdir ${ABOVEWEBROOT}/dokuwiki.data
cp -a ${WEBROOT}/data/* ${ABOVEWEBROOT}/dokuwiki.data
rm -r ${WEBROOT}/data

mkdir ${ABOVEWEBROOT}/dokuwiki.bin
cp -a ${WEBROOT}/bin/* ${ABOVEWEBROOT}/dokuwiki.bin
rm -r ${WEBROOT}/bin

mkdir ${ABOVEWEBROOT}/dokuwiki.conf
cp -a ${WEBROOT}/conf/* ${ABOVEWEBROOT}/dokuwiki.conf
rm -r ${WEBROOT}/conf
semanage fcontext -d -t httpd_sys_rw_content_t "${ABOVEWEBROOT}/conf(/.*)?"
restorecon -R -v ${WEBROOT}/conf

semanage fcontext -a -t httpd_sys_rw_content_t "${ABOVEWEBROOT}/conf/local.php
restorecon -v ${ABOVEWEBROOT}/conf/local.php
semanage fcontext -a -t httpd_sys_rw_content_t "${ABOVEWEBROOT}/conf/local.php.bak
restorecon -v ${ABOVEWEBROOT}/conf/local.php.bak
semanage fcontext -a -t httpd_sys_rw_content_t "${ABOVEWEBROOT}/conf/users.auth.php
restorecon -v ${ABOVEWEBROOT}/conf/users.auth.php
semanage fcontext -a -t httpd_sys_rw_content_t "${ABOVEWEBROOT}/conf/acl.auth.php
restorecon -v ${ABOVEWEBROOT}/conf/acl.auth.php
semanage fcontext -a -t httpd_sys_rw_content_t "${ABOVEWEBROOT}/conf/plugins.local.php
restorecon -v ${ABOVEWEBROOT}/conf/plugins.local.php
semanage fcontext -a -t httpd_sys_rw_content_t "${ABOVEWEBROOT}/conf/plugins.local.php.bak
restorecon -v ${ABOVEWEBROOT}/conf/plugins.local.php.bak

cat > ${WEBROOT}/inc/preload.php <<EOF
<?php
// DO NOT use a closing php tag. This causes a problem with the feeds,
// among other things. For more information on this issue, please see:w
// http://www.dokuwiki.org/devel:coding_style#php_closing_tags
 
define('DOKU_CONF','${ABOVEWEBROOT}/dokuwiki.conf/');
EOF

chown ${WWW_DATA_USER_NAME}:${WWW_DATA_GROUP_NAME} ${WEBROOT}/inc/preload.php

echo "$conf['savedir'] = '/home/yourname/data';" >> ${ABOVEWEBROOT}/dokuwiki.conf/local.php


#rm -r ${TEMP}
exit 0
