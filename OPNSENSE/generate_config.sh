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
TIMEZONE="Etc/UTC"

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
ROOT_PASSWORD_HASH='$2y$10$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS'

if [ "$MODE" = "1" ]; then
  WAN_IP_BLOCK="<ipaddr>dhcp</ipaddr>"
  WAN_GATEWAY_BLOCK=""
  WAN_DNS=""
elif [ "$MODE" = "2" ]; then
  read -rp "WAN IP address: " WAN_IP
  read -rp "WAN CIDR (e.g. 24): " WAN_CIDR
  read -rp "WAN Gateway: " WAN_GW
  read -rp "WAN dns: " WAN_DNS

  WAN_DNS_BLOCK="<dnsserver>${WAN_DNS}</dnsserver>"

  WAN_IP_BLOCK="<ipaddr>${WAN_IP}</ipaddr>
      <subnet>${WAN_CIDR}</subnet>
      <gateway>WAN_GW</gateway>"

  WAN_GATEWAY_BLOCK="<gateways>
    <gateway_item>
      <disabled>0</disabled>
      <interface>wan</interface>
      <gateway>${WAN_GW}</gateway>
      <name>WAN_GW</name>
      <ipprotocol>inet</ipprotocol>
      <defaultgw>1</defaultgw>
      <weight>1</weight>
      <priority>255</priority>
    </gateway_item>
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
    <group>
      <name>admins</name>
      <description>System Administrators</description>
      <scope>system</scope>
      <gid>1999</gid>
      <member>0</member>
      <priv>page-all</priv>
    </group>
    <user>
      <name>root</name>
      <descr>System Administrator</descr>
      <scope>system</scope>
      <groupname>admins</groupname>
      <password>${ROOT_PASSWORD_HASH}</password>
      <uid>0</uid>
    </user>
    <ssh>
      <group>admins</group>
      <noauto>1</noauto>
      <interfaces/>
      <kex/>
      <ciphers/>
      <macs/>
      <keys/>
      <keysig/>
      <passwordauth>1</passwordauth>
      <permitrootlogin>1</permitrootlogin>
      <enabled>enabled</enabled>  
    </ssh>
  ${WAN_DNS_BLOCK}
  <nohttpreferercheck>yes</nohttpreferercheck>
  <disablechecksumoffloading>1</disablechecksumoffloading>
  <disablesegmentationoffloading>1</disablesegmentationoffloading>
  <disablelargereceiveoffloading>1</disablelargereceiveoffloading>
  <disablevlanhwfilter>1</disablevlanhwfilter>
  </system>
  <unbound>
    <enable>1</enable>
    <dnssec>0</dnssec>
    <active_interface>all</active_interface>
    <outgoing_interface>wan</outgoing_interface>
    <registerdhcp>1</registerdhcp>
    <registersystem>1</registersystem>
  </unbound>
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
    <rule>
      <type>pass</type>
      <ipprotocol>inet</ipprotocol>
      <descr>Default allow LAN2 to any rule</descr>
      <interface>opt1</interface>
      <source>
        <network>opt1</network>
      </source>
      <destination>
        <any/>
      </destination>
    </rule>  
    <rule>
      <type>pass</type>
      <ipprotocol>inet</ipprotocol>
      <interface>opt2</interface>
      <source>
        <network>opt2</network>
      </source>
      <destination>
        <any/>
      </destination>
    </rule>
  </filter>
  ${WAN_GATEWAY_BLOCK}
</opnsense>
EOF

echo
echo "✔ WAN config generated at /root/opnsense/config.xml"
