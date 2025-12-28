#!/bin/bash
set -e

mkdir -p $(pwd)/OPNSENSE/iso/conf

echo "=== OPNsense WAN IP Configuration ==="
echo "1) DHCP"
echo "2) Static"
read -rp "Select WAN mode [1-2]: " MODE

WAN_IF="vtnet1"
LAN_IF="vtnet0"
LAN2_IF="vtnet2"
OOBM_IF="vtnet3"

HOSTNAME="opnsense"
DOMAIN="local"
TIMEZONE="UTC"

# LAN defaults
LAN_IP="192.168.1.1"
LAN_CIDR="24"

# LAN2 defaults
LAN2_IP="192.168.2.1"
LAN2_CIDR="24"

# OOBM defaults
OOBM_IP="172.20.0.2"
OOBM_CIDR="24"

WAN_DNS=""

# Default password: opnsense
ROOT_PASSWORD_HASH='$2y$10$u1rPZJvM0Qz9sPZP6UZZ6OaGxK2p2pF0XjU5O4Hn5qjz'

if [ "$MODE" = "1" ]; then
  WAN_IP_BLOCK="<ipaddr>dhcp</ipaddr>"
  WAN_GATEWAY_BLOCK=""
elif [ "$MODE" = "2" ]; then
  read -rp "WAN IP address: " WAN_IP
  read -rp "WAN CIDR (e.g. 24): " WAN_CIDR
  read -rp "WAN Gateway: " WAN_GW
  read -rp "WAN dns: " WAN_DNS

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

cat > $(pwd)/OPNSENSE/iso/conf/config.xml <<EOF
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
    <ssh>
      <group>admins</group>
      <noauto>1</noauto>
      <interfaces>lan,opt1,opt2</interfaces>
      <kex/>
      <ciphers/>
      <macs/>
      <keys/>
      <keysig/>
      <enabled>enabled</enabled>
      <permitrootlogin>1</permitrootlogin>
      <passwordauth>1</passwordauth>
    </ssh>
    <dnsserver>${WAN_DNS}</dnsserver>
  </system>

  <interfaces>
    <wan>
      <enable>1</enable>
      <if>${WAN_IF}</if>
      ${WAN_IP_BLOCK}
      <descr>wan</descr>
    </wan>

    <lan>
      <enable>1</enable>
      <if>${LAN_IF}</if>
      <descr>lan1</descr>
      <ipaddr>${LAN_IP}</ipaddr>
      <subnet>${LAN_CIDR}</subnet>
    </lan>

    <opt1>
      <enable>1</enable>
      <if>${LAN2_IF}</if>
      <descr>lan2</descr>
      <ipaddr>${LAN2_IP}</ipaddr>
      <subnet>${LAN2_CIDR}</subnet>
    </opt1>
    <opt2>
      <enable>1</enable>
      <if>${OOBM_IF}</if>
      <descr>oobm</descr>
      <ipaddr>${OOBM_IP}</ipaddr>
      <subnet>${OOBM_CIDR}</subnet>
    </opt2>
    
    
  </interfaces>

  ${WAN_GATEWAY_BLOCK}
</opnsense>
EOF

echo
echo "✔ WAN config generated at /root/opnsense/config.xml"
