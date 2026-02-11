#!/bin/bash
set -euo pipefail

echo ">>> Enable IPv4 forwarding"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-lab-ipforward.conf
sysctl -p /etc/sysctl.d/99-lab-ipforward.conf

# ============================
# INTERFACES
# ============================
ETH_OUT="eth0"      # outside / WAN
ETH_LAB="eth1"      # 172.20.0.0/24 network
ETH_LAB2="eth2"     # 172.30.0.0/24 network

GUAC_LAB_IP="172.20.0.1"
GUAC_LAB2_IP=$(ip -4 addr show "$ETH_LAB2" | awk '/inet / {print $2}' | cut -d/ -f1)

# ============================
# CLEAN OLD RULES (optional but recommended)
# ============================
iptables -F
iptables -t nat -F

# Allow established traffic first
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# ============================
# PROXMOX (172.30.0.100 via eth2)
# ============================
echo ">>> NAT: Proxmox"

PROXMOX_IP="172.30.0.100"
PROXMOX_PORT=8006
PROXMOX_OUTSIDE=9001   # http://GUAC:9001

# DNAT
iptables -t nat -A PREROUTING -i $ETH_OUT -p tcp --dport $PROXMOX_OUTSIDE \
  -j DNAT --to-destination $PROXMOX_IP:$PROXMOX_PORT

# SNAT
iptables -t nat -A POSTROUTING -o $ETH_LAB2 -d $PROXMOX_IP -p tcp --dport $PROXMOX_PORT \
  -j SNAT --to-source $GUAC_LAB2_IP

# Forward rule
iptables -A FORWARD -i $ETH_OUT -o $ETH_LAB2 -p tcp --dport $PROXMOX_PORT -j ACCEPT


# ============================
# WAZUH (172.20.0.20 via eth1)
# ============================
echo ">>> NAT: Wazuh"

WAZUH_IP="172.20.0.20"
WAZUH_PORT=443
WAZUH_OUTSIDE=9002   # https://GUAC:9002

iptables -t nat -A PREROUTING -i $ETH_OUT -p tcp --dport $WAZUH_OUTSIDE \
  -j DNAT --to-destination $WAZUH_IP:$WAZUH_PORT

iptables -t nat -A POSTROUTING -o $ETH_LAB -d $WAZUH_IP -p tcp --dport $WAZUH_PORT \
  -j SNAT --to-source $GUAC_LAB_IP

iptables -A FORWARD -i $ETH_OUT -o $ETH_LAB -p tcp --dport $WAZUH_PORT -j ACCEPT


# ============================
# OPNsense (172.20.0.2 via eth1)
# ============================
echo ">>> NAT: OPNsense"

OPNSENSE_IP="172.20.0.2"
OPNSENSE_PORT=443
OPNSENSE_OUTSIDE=9003   # https://GUAC:9003

iptables -t nat -A PREROUTING -i $ETH_OUT -p tcp --dport $OPNSENSE_OUTSIDE \
  -j DNAT --to-destination $OPNSENSE_IP:$OPNSENSE_PORT

iptables -t nat -A POSTROUTING -o $ETH_LAB -d $OPNSENSE_IP -p tcp --dport $OPNSENSE_PORT \
  -j SNAT --to-source $GUAC_LAB_IP

iptables -A FORWARD -i $ETH_OUT -o $ETH_LAB -p tcp --dport $OPNSENSE_PORT -j ACCEPT


# ============================
# SAVE PERSISTENT
# ============================
echo ">>> Save NAT rules"

DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
netfilter-persistent save

echo ">>> NAT configuration complete."
