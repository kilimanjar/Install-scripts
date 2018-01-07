#!/bin/bash

echo "alias ls='ls -la --color=auto --group-directories-first'" >> /etc/skel/.bashrc
echo "alias ls='ls -la --color=auto --group-directories-first'" >> ~/.bashrc

yum autoremove -y dhclient wpa_supplicant plymouth iwl* ivtv-firmware alsa-firmware aic94xx-firmware
yum update
yum install nano curl wget bash-completion setools-console policycoreutils-python iptables-services epel-release

systemctl disable firewalld
yum autoremove -y firewalld
systemctl enable iptables
systemctl start iptables
systemctl enable ip6tables
systemctl start ip6tables

exit 0
