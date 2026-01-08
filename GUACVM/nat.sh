#!/bin/bash
set -e

echo ">>> Enable IPv4 forwarding"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-lab-ipforward.conf
sysctl -p /etc/sysctl.d/99-lab-ipforward.conf

# ============================
# INTERFACES
# ============================
ETH_OUT="eth0"      # outside / WAN
ETH_LAB="eth1"      # lab LAN interface
GUAC_LAB_IP="172.20.0.1"

# ============================
# PROXMOX
# ============================
echo ">>> NAT: Proxmox"

PROXMOX_IP="172.20.0.100"
PROXMOX_PORT=8006
PROXMOX_OUTSIDE=9001   # http://GUAC:9001

iptables -t nat -A PREROUTING -i $ETH_OUT -p tcp --dport $PROXMOX_OUTSIDE \
  -j DNAT --to-destination $PROXMOX_IP:$PROXMOX_PORT

iptables -t nat -A POSTROUTING -o $ETH_LAB -d $PROXMOX_IP -p tcp --dport $PROXMOX_PORT \
  -j SNAT --to-source $GUAC_LAB_IP

iptables -I FORWARD -i $ETH_OUT -o $ETH_LAB -p tcp --dport $PROXMOX_PORT -j ACCEPT
iptables -I FORWARD -i $ETH_LAB -o $ETH_OUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ============================
# WAZUH
# ============================
echo ">>> NAT: Wazuh"

WAZUH_IP="172.20.0.20"
WAZUH_PORT=443
WAZUH_OUTSIDE=9002   # https://GUAC:9002

iptables -t nat -A PREROUTING -i $ETH_OUT -p tcp --dport $WAZUH_OUTSIDE \
  -j DNAT --to-destination $WAZUH_IP:$WAZUH_PORT

iptables -t nat -A POSTROUTING -o $ETH_LAB -d $WAZUH_IP -p tcp --dport $WAZUH_PORT \
  -j SNAT --to-source $GUAC_LAB_IP

iptables -I FORWARD -i $ETH_OUT -o $ETH_LAB -p tcp --dport $WAZUH_PORT -j ACCEPT
iptables -I FORWARD -i $ETH_LAB -o $ETH_OUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ============================
# OPNsense
# ============================
echo ">>> NAT: OPNsense"

OPNSENSE_IP="172.20.0.2"
OPNSENSE_PORT=80
OPNSENSE_OUTSIDE=9003   # http://GUAC:9003

iptables -t nat -A PREROUTING -i $ETH_OUT -p tcp --dport $OPNSENSE_OUTSIDE \
  -j DNAT --to-destination $OPNSENSE_IP:$OPNSENSE_PORT

iptables -t nat -A POSTROUTING -o $ETH_LAB -d $OPNSENSE_IP -p tcp --dport $OPNSENSE_PORT \
  -j SNAT --to-source $GUAC_LAB_IP

iptables -I FORWARD -i $ETH_OUT -o $ETH_LAB -p tcp --dport $OPNSENSE_PORT -j ACCEPT
iptables -I FORWARD -i $ETH_LAB -o $ETH_OUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ============================
# SAVE PERSISTENT
# ============================
echo ">>> Save NAT rules"

DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
netfilter-persistent save

echo ">>> NAT configuration complete."
