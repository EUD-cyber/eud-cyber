#!/bin/bash
set -e

mkdir -p /root/opnsense

echo "=== OPNsense WAN IP Configuration ==="
echo "1) DHCP"
echo "2) Static"
read -rp "Select WAN mode [1-2]: " MODE

WAN_IF="vtnet0"
LAN_IF="vtnet1"

HOSTNAME="opnsense"
DOMAIN="local"
TIMEZONE="UTC"

# LAN defaults
LAN_IP="192.168.10.1"
LAN_CIDR="24"

# Default password: opnsense
ROOT_PASSWORD_HASH='$2y$10$u1rPZJvM0Qz9sPZP6UZZ6OaGxK2p2pF0XjU5O4Hn5qjz'

if [ "$MODE" = "1" ]; then
  WAN_IP_BLOCK="<ipaddr>dhcp</ipaddr>"
  WAN_GATEWAY_BLOCK=""
elif [ "$MODE" = "2" ]; then
  read -rp "WAN IP address: " WAN_IP
  read -rp "WAN CIDR (e.g. 24): " WAN_CIDR
  read -rp "WAN Gateway: " WAN_GW

  WAN_IP_BLOCK="<ipaddr>${WAN_IP}</ipaddr>
      <subnet>${WAN_CIDR}</subnet>"

  WAN_GATEWAY_BLOCK="<gateways>
    <gateway>
      <interface>wan</interface>
      <gateway>${WAN_GW}</gateway>
      <name>WAN_GW</name>
    </gateway>
  </gateways>"
else
  echo "Invalid selection"
  exit 1
fi

cat > /root/opnsense/config.xml <<EOF
<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>${HOSTNAME}</hostname>
    <domain>${DOMAIN}</domain>
    <timezone>${TIMEZONE}</timezone>
    <ssh>
      <enable>1</enable>
    </ssh>
    <user>
      <name>root</name>
      <password>${ROOT_PASSWORD_HASH}</password>
      <uid>0</uid>
      <scope>system</scope>
    </user>
  </system>

  <interfaces>
    <wan>
      <enable>1</enable>
      <if>${WAN_IF}</if>
      ${WAN_IP_BLOCK}
      <descr>WAN Gateway</descr>
    </wan>

    <lan>
      <enable>1</enable>
      <if>${LAN_IF}</if>
      <ipaddr>${LAN_IP}</ipaddr>
      <subnet>${LAN_CIDR}</subnet>
    </lan>
  </interfaces>

  ${WAN_GATEWAY_BLOCK}
</opnsense>
EOF

echo
echo "✔ WAN config generated at /root/opnsense/config.xml"
