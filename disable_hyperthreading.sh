#!/bin/bash

cat > /root/disable_hyperthreading.sh <<EOF
#!/bin/bash
for CPU in /sys/devices/system/cpu/cpu[0-9]*; do
    CPUID=`basename $CPU | cut -b4-`
    echo -en "CPU: $CPUID\t"
    [ -e $CPU/online ] && echo "1" > $CPU/online
    THREAD1=`cat $CPU/topology/thread_siblings_list | cut -f1 -d,`
    if [ $CPUID = $THREAD1 ]; then
        echo "-> enable"
        [ -e $CPU/online ] && echo "1" > $CPU/online
    else
        echo "-> disable"
        echo "0" > $CPU/online
    fi
done
exit 0
EOF

cat > /etc/systemd/system/disable-hyperthreading.service <<EOF
[Unit]
Description=Disable Hyperthreading on Intel CPU
 
[Service]
ExecStart=/root/disable_hyperthreading.sh
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
EOF
