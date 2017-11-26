#!/bin/bash
DEST_FILE="/etc/rsyslog.conf"

yum -y install rsyslog

f [ -f ${DEST_FILE} ]; then
    cp -a ${DEST_FILE} ${DEST_FILE}.backup-$(date +%F)
fi

cat > /etc/rsyslog.conf <<'EOF'
#### MODULES ####

# The imjournal module bellow is now used as a message source instead of imuxsock.
$ModLoad imuxsock # provides support for local system logging (e.g. via logger command)
$ModLoad imjournal # provides access to the systemd journal
#$ModLoad imklog # reads kernel messages (the same are read from journald)
#$ModLoad immark  # provides --MARK-- message capability

# Provides UDP syslog reception
#$ModLoad imudp
#$UDPServerRun 514

# Provides TCP syslog reception
#$ModLoad imtcp
#$InputTCPServerRun 514


#### GLOBAL DIRECTIVES ####
# In CentOS
$WorkDirectory /var/lib/rsyslog
# In Debian
#$WorkDirectory /var/spool/rsyslog

# Use default timestamp format
#$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# File syncing capability is disabled by default. This feature is usually not required,
# not useful and an extreme performance hit
#$ActionFileEnableSync on

# Include all config files in /etc/rsyslog.d/
$IncludeConfig /etc/rsyslog.d/*.conf

# Turn off message reception via local log socket;
# local messages are retrieved through imjournal now.
$OmitLocalLogging on

# File to store the position in the journal
$IMJournalStateFile imjournal.state


#### RULES ####

*.emerg                                                 :omusrmsg:*
kern,daemon.crit                                        /dev/console
*.*                                                     /var/log/messages
auth.*                                                  /var/log/auth.log
authpriv.*                                              /var/log/authpriv.log
cron.*                                                  /var/log/cron.log
daemon.*                                                /var/log/daemon.log
ftp.*                                                   /var/log/ftp.log
kern.*                                                  /var/log/kern.log
lpr.*                                                   /var/log/lpr.log
mail.*                                                  /var/log/mail.log
news.*                                                  /var/log/news.log
syslog.*                                                /var/log/syslog.log
user.*                                                  /var/log/user.log
uucp.*                                                  /var/log/uucp.log
local0.*                                                /var/log/local0.log
local1.*                                                /var/log/local1.log
local2.*                                                /var/log/local2.log
local3.*                                                /var/log/local3.log
local4.*                                                /var/log/local4.log
local5.*                                                /var/log/local5.log
local6.*                                                /var/log/local6.log
local7.*                                                /var/log/local7.log

# ### begin forwarding rule ###
# The statement between the begin ... end define a SINGLE forwarding
# rule. They belong together, do NOT split them. If you create multiple
# forwarding rules, duplicate the whole block!
# Remote Logging (we use TCP for reliable delivery)
#
# An on-disk queue is created for this action. If the remote host is
# down, messages are spooled to disk and sent when it is up again.
#$ActionQueueFileName fwdRule1 # unique name prefix for spool files
#$ActionQueueMaxDiskSpace 1g   # 1gb space limit (use as much as possible)
#$ActionQueueSaveOnShutdown on # save messages to disk on shutdown
#$ActionQueueType LinkedList   # run asynchronously
#$ActionResumeRetryCount -1    # infinite retries if host is down
# remote host is: name/ip:port, e.g. 192.168.0.1:514, port optional
#*.* @@remote-host:514
# ### end of the forwarding rule ###
EOF

systemctl restart rsyslog

exit 0
