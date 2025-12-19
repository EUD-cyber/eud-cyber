#!/bin/bash
set -e

echo "=== OPNsense LAN Configuration ==="

HOSTNAME="opnsense"
DOMAIN=="cloud.local"
TIMEZONE="UTC"

echo
echo "Choose WAN IP configuration:"
echo "1) DHCP"
echo "2) Static"
read -p "Enter choice [1-2]: " choice

if [ "$choice" = "1" ]; then
    IP_ADDR="ip=dhcp"
    DNS_SERVER=""

elif [ "$choice" = "2" ]; then
    read -p "Enter static IP (e.g., 192.168.1.100/24): " STATIC_IP
    read -p "Enter gateway (e.g., 192.168.1.1): " GATEWAY
    read -p "Enter DNS servers (space separated, e.g., 8.8.8.8 1.1.1.1): " DNS

    IP_ADDR="ip=${STATIC_IP},gw=${GATEWAY}"
    DNS_SERVER="$DNS"

else
    echo "Invalid choice. Exiting."
    exit 1
fi

WAN_IF="vtnet0"
LAN_IF="vtnet1"

  read -rp " IP address (e.g. 192.168.10.1): " LAN_IP
  read -rp "LAN CIDR (e.g. 24): " LAN_CIDR
  read -rp "DHCP range start: " DHCP_START
  read -rp "DHCP range end: " DHCP_END

  LAN_IP_BLOCK="<ipaddr>${LAN_IP}</ipaddr>
      <subnet>${LAN_CIDR}</subnet>"

  DHCPD_BLOCK="<dhcpd>
    <lan>
      <enable>1</enable>
      <range>
        <from>${DHCP_START}</from>
        <to>${DHCP_END}</to>
      </range>
    </lan>
  </dhcpd>"
else
  LAN_IP_BLOCK="<ipaddr>dhcp</ipaddr>"
  DHCPD_BLOCK=""
fi

# Default password: opnsense
ROOT_PASSWORD_HASH='$2y$10$u1rPZJvM0Qz9sPZP6UZZ6OaGxK2p2pF0XjU5O4Hn5qjz'

export HOSTNAME DOMAIN TIMEZONE WAN_IF LAN_IF LAN_IP_BLOCK DHCPD_BLOCK ROOT_PASSWORD_HASH

envsubst < /root/opnsense/config.xml.tpl > /root/opnsense/config.xml

echo
echo "✔ Generated /root/opnsense/config.xml"
