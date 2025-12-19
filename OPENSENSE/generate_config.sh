#!/bin/bash
set -e

echo "=== OPNsense LAN Configuration ==="

HOSTNAME="opnsense"
DOMAIN=="cloud.local"
TIMEZONE="UTC"
WAN_IF="vtnet0"
LAN_IF="vtnet1"

echo
echo "Choose WAN IP configuration:"
echo "1) DHCP"
echo "2) Static"
read -p "Enter choice [1-2]: " choice

if [ "$choice" = "1" ]; then
    IP_ADDR="ip=dhcp"
    DNS_SERVER=""

elif [ "$choice" = "2" ]; then
    read -p "Enter WAN Static ip (e.g., 192.168.1.100): " WAN_IP
    read -p "Enter WAN subnet without / (e.g, 24): " WAN_SUB
    read -p "Enter WAN Gateway (e.g., 192.168.1.1): " WAN_GW


else
    echo "Invalid choice. Exiting."
    exit 1
fi


  
  
  

# Default password: opnsense
ROOT_PASSWORD_HASH='$2y$10$u1rPZJvM0Qz9sPZP6UZZ6OaGxK2p2pF0XjU5O4Hn5qjz'

export HOSTNAME DOMAIN TIMEZONE WAN_IF LAN_IF WAN_IP WAN_SUB WAN_GW ROOT_PASSWORD_HASH

envsubst < /root/opnsense/config.xml.tpl > /root/opnsense/config.xml

echo
echo "✔ Generated /root/opnsense/config.xml"
