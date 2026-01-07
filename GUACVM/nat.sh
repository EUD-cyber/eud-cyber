#!/bin/bash
set -e

echo ">>> Enable IPv4 forwarding"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-lab-ipforward.conf
sysctl -p /etc/sysctl.d/99-lab-ipforward.conf

# ----------------------------
# VARS
# ----------------------------
PROXMOX_IP="172.20.0.100"
GUAC_LAB_IP="172.20.0.1"

OUTSIDE_PORT=9001
PROXMOX_PORT=8006

ETH_OUT="eth0"
ETH_LAB="eth1"

echo ">>> Add DNAT (GUAC -> Proxmox)"
iptables -t nat -A PREROUTING -i $ETH_OUT -p tcp --dport $OUTSIDE_PORT \
  -j DNAT --to-destination $PROXMOX_IP:$PROXMOX_PORT

echo ">>> Add SNAT (return traffic back through Guac)"
iptables -t nat -A POSTROUTING -o $ETH_LAB -d $PROXMOX_IP -p tcp --dport $PROXMOX_PORT \
  -j SNAT --to-source $GUAC_LAB_IP

echo ">>> Allow traffic forwarding"
iptables -I FORWARD -i $ETH_OUT -o $ETH_LAB -p tcp --dport $PROXMOX_PORT -j ACCEPT
iptables -I FORWARD -i $ETH_LAB -o $ETH_OUT -m state --state ESTABLISHED,RELATED -j ACCEPT

echo ">>> Save rules"
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
netfilter-persistent save

echo ">>> Done."
