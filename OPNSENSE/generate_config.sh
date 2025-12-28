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
    <gateway item>
      <interface>wan</interface>
      <gateway>${WAN_GW}</gateway>
      <name>WAN_GW</name>
      <ipprotocol>inet</ipprotocol>
      <defaultgw>1</defaultgw>
    </gateway item>
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
    <user>
      <name>root</name>
      <password>${ROOT_PASSWORD_HASH}</password>
      <uid>0</uid>
      <scope>system</scope>
      <groupname>admins</groupname>
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

  <nat>
    <outbound>
      <mode>automatic</mode>
    </outbound>
</nat>

<filter>
  <rule>
    <rule uuid="63376c20-f433-4f7a-b7af-9a74fce396d4">
      <type>pass</type>
      <ipprotocol>inet</ipprotocol>
      <descr>Default allow LAN to any rule</descr>
      <interface>lan</interface>
      <source>
        <network>lan</network>
      </source>
      <destination>
        <any/>
      </destination>
  </rule>
    <rule uuid="7780d053-9d65-4db8-8763-1a2dea6b4f27">
      <type>pass</type>
      <interface>opt1</interface>
      <ipprotocol>inet</ipprotocol>
      <statetype>keep state</statetype>
      <descr>Default allow LAN to any rule</descr>
      <direction>in</direction>
      <quick>1</quick>
      <source>
        <network>opt1</network>
      </source>
      <destination>
        <any>1</any>
      </destination>
  </rule>
    <rule uuid="df90bc4c-7244-479e-b5d3-7722d2be0a6d">
      <type>pass</type>
      <interface>opt2</interface>
      <ipprotocol>inet</ipprotocol>
      <statetype>keep state</statetype>
      <direction>in</direction>
      <quick>1</quick>
      <source>
        <any>1</any>
      </source>
      <destination>
        <any>1</any>
      </destination>
  </rule>
</filter>

  ${WAN_GATEWAY_BLOCK}
</opnsense>
EOF

echo
echo "✔ WAN config generated at /root/opnsense/config.xml"
