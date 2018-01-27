#!/bin/bash

sudo groupadd libvirt
sudo usermod -a -G libvirt ${USERNAME}

cat > /etc/polkit-1/localauthority/50-local.d/80-libvirt.rules <<EOF
polkit.addRule(function(action, subject) {
 if (action.id == "org.libvirt.unix.manage" && subject.local && subject.active && subject.isInGroup("libvirt")) {
 return polkit.Result.YES;
 }
});
EOF
