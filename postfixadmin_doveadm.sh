#!/bin/bash

# Setting:
# $CONF['encrypt'] = 'dovecot:SHA512-CRYPT';
# $CONF['dovecotpw'] = "/usr/bin/doveadm pw";
# in postfixadmin's config.local.php 
# caused problems to access /etc/dovecot/dovecot.conf in SElinux environment (Centos 7).
#
# Solution copied from this comment: https://github.com/opensolutions/ViMbAdmin/issues/95#issuecomment-121966988
#
# Citation:
# In my case, this error was caused by SELinux preventing doveadm to access the files in /etc/dovecot.
#
# sudo -u nginx /usr/bin/doveadm pw -s 'SHA512-CRYPT' -u 'something@somewhere.com' -p 'password'
# (the command line that's passed by ViMbAdmin) worked fine, so it had to be something else.
#
# /var/log/audit/audit.log (I always check SELinux last 😛) had entries suggesting that doveadm was called from httpd_t context, and not allowed to access the dovecot_etc_t context of the dovecot config files.
# This TE file solved it for me:
#--------------------------------------------------------------------------------------------------------


cat > doveadm.te <<EOF
# doveadm.te
# This module is required to get ViMbAdmin working correctly with the
# dovecot:SHA512-CRYPT password scheme.
# Since it's being called from a httpd_t context, doveadm cannot access
# the dovecot_etc_t context of the config files.
# See also https://github.com/opensolutions/ViMbAdmin/issues/95

module doveadm 1.0;

require {
        type dovecot_etc_t;
        type httpd_t;
        class file { read getattr open };
        class dir read;
}

#============= httpd_t ==============
allow httpd_t dovecot_etc_t:file { read getattr open };
allow httpd_t dovecot_etc_t:dir read;
EOF

# Compile and install it with

checkmodule -M -m -o doveadm.mod doveadm.te
semodule_package -o doveadm.pp -m doveadm.mod
semodule -i doveadm.pp

exit 0
