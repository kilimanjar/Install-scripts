#!/bin/bash
DEST_FILE="/etc/logrotate.d/rsyslog"

if [ -f ${DEST_FILE} ]; then
    rm ${DEST_FILE}
fi

cat > ${DEST_FILE} <<EOF
/var/log/auth.log
/var/log/authpriv.log
/var/log/cron.log
/var/log/daemon.log
/var/log/ftp.log
/var/log/kern.log
/var/log/lpr.log
/var/log/mail.log
/var/log/news.log
/var/log/syslog.log
/var/log/user.log
/var/log/uucp.log
/var/log/local0.log
/var/log/local1.log
/var/log/local2.log
/var/log/local3.log
/var/log/local4.log
/var/log/local5.log
/var/log/local6.log
/var/log/local7.log
/var/log/debug
/var/log/messages
{
    rotate 50
    daily
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
# In Debian
#    invoke-rc.d rsyslog rotate > /dev/null
# In CentOS
    /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
EOF

exit 0
