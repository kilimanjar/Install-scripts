#!/bin/bash
# from: https://blog.christophersmart.com/2017/02/08/manage-intel-turbo-boost-with-systemd/

cat > /etc/systemd/system/disable-turbo-boost.service <<EOF
[Unit]
Description=Disable Turbo Boost on Intel CPU
 
[Service]
ExecStart=/bin/sh -c "/usr/bin/echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo"
ExecStop=/bin/sh -c "/usr/bin/echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo"
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
EOF
