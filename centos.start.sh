#!/bin/bash

echo "alias ls='ls -la --color=auto --group-directories-first'" >> ~/.bashrc

yum remove -y dhclient
yum update
yum install nano curl wget bash-completion setools-console policycoreutils-python iptables-services epel-release

systemctl disable firewalld
systemctl enable iptables
systemctl start iptables
systemctl enable ip6tables
systemctl start ip6tables

exit 0
